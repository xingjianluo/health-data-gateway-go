package gateway

import (
	"sync"
	"time"
)

// batchWorkers 单批次内并发处理主体的 worker 数上限（本地大并发但结果不丢）
const batchWorkers = 8

// MaxBatchSubjects 单个批次允许访问的最大主体数量
const MaxBatchSubjects = 100

// BatchAccess 批量访问入口：
//   - 同一批所有主体固定使用同一个判断时刻与同一个策略版本；
//   - 每个主体独立判定、独立最小化脱敏、独立写审计，互不拖垮、互不串数据；
//   - 结果顺序与请求主体顺序严格一致，并给出整批汇总；
//   - 通过 IdempotencyKey 保证重试/断点重跑不重复返回、不重复读取、不重复审计。
func (g *Gateway) BatchAccess(req BatchRequest) BatchResponse {
	// 幂等控制：相同键的重试直接复用首次结论
	key := req.IdempotencyKey
	if cached, acquire := g.idem.begin(key); !acquire {
		if cached.BatchID != "" {
			return cloneBatchResponse(cached)
		}
		// 同键正在处理：等待其落定，避免并发重入造成重复处理与重复审计
		if finished, ok := g.idem.wait(key); ok {
			return cloneBatchResponse(finished)
		}
	}

	resp := g.runBatch(req)
	g.idem.finish(key, resp)
	return cloneBatchResponse(resp)
}

// runBatch 执行一次批次：先做入口校验（可能整体拒绝），再固定口径并逐主体处理
func (g *Gateway) runBatch(req BatchRequest) BatchResponse {
	batchID := g.newBatchID()
	now := g.clock()

	// 1. 入口校验：空批次 / 重复主体 / 超上限 -> 整批清楚拒绝，不处理任何主体
	if reason, msg := validateBatch(req.Subjects); reason != ReasonAllowed {
		resp := BatchResponse{
			BatchID:  batchID,
			Rejected: true,
			Reason:   reason,
			Message:  msg,
			Purpose:  req.Purpose,
			Category: req.Category,
		}
		g.writeBatchHead(batchID, req, resp, now, "", 0)
		return resp
	}

	// 2. 固定整批口径：判断时刻只取一次，策略版本只解析一次
	evaluatedAt := now
	pol, hasPolicy := g.resolvePolicy(req.Version)
	if !hasPolicy {
		resp := BatchResponse{
			BatchID:  batchID,
			Rejected: true,
			Reason:   ReasonPolicyVersionMissing,
			Message:  "策略版本不存在: " + req.Version,
			Purpose:  req.Purpose,
			Category: req.Category,
		}
		g.writeBatchHead(batchID, req, resp, evaluatedAt, req.Version, 0)
		return resp
	}

	n := len(req.Subjects)
	outcomes := make([]SubjectOutcome, n)

	// 3. 并发独立处理：每个主体一个稳定下标槽位，互不覆盖、不串位
	workers := batchWorkers
	if n < workers {
		workers = n
	}
	var wg sync.WaitGroup
	jobs := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				subject := req.Subjects[i]
				resp := g.access(AccessRequest{
					Entry:    req.Entry,
					Subject:  subject,
					Purpose:  req.Purpose,
					Category: req.Category,
					Fields:   req.Fields,
					Version:  pol.Version, // 固定版本，保证整批口径一致
				}, evaluatedAt, batchCtx{
					batchID:      batchID,
					subjectIndex: i,
					evaluatedAt:  evaluatedAt,
					version:      pol.Version,
				})
				outcomes[i] = SubjectOutcome{
					Index:    i,
					Subject:  subject,
					Status:   outcomeOf(resp.Decision, resp.Skipped),
					Decision: resp.Decision,
					AuditID:  resp.AuditID,
					Record:   cloneRecord(resp.Record),
					Note:     g.subjectNote(resp),
				}
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	// 4. 汇总（顺序已由下标槽位固定，这里直接统计）
	var sum BatchSummary
	sum.Total = n
	for _, o := range outcomes {
		switch o.Status {
		case StatusAllowed:
			sum.Allowed++
		case StatusDenied:
			sum.Denied++
		case StatusDegraded:
			sum.Degraded++
		}
	}

	resp := BatchResponse{
		BatchID:       batchID,
		Purpose:       req.Purpose,
		Category:      req.Category,
		PolicyVersion: pol.Version,
		EvaluatedAt:   evaluatedAt,
		Outcomes:      outcomes,
		Summary:       sum,
	}
	// 5. 整批关联：写一条批次汇总审计记录，与每个主体的记录通过 BatchID 关联
	g.writeBatchHead(batchID, req, resp, evaluatedAt, pol.Version, n)
	return resp
}

// validateBatch 校验批次主体列表，返回互斥的批次级拒绝原因
func validateBatch(subjects []SubjectID) (DenyReason, string) {
	if len(subjects) == 0 {
		return ReasonBatchEmpty, "批量请求必须至少包含一个数据主体"
	}
	if len(subjects) > MaxBatchSubjects {
		return ReasonBatchTooLarge, "批量主体数 " + itoa(len(subjects)) +
			" 超过上限 " + itoa(MaxBatchSubjects)
	}
	seen := make(map[SubjectID]bool, len(subjects))
	for _, s := range subjects {
		if seen[s] {
			return ReasonBatchDuplicateSubject, "同一批次内主体重复: " + string(s)
		}
		seen[s] = true
	}
	return ReasonAllowed, ""
}

// resolvePolicy 解析整批固定使用的策略版本（显式版本或当前最新版本）
func (g *Gateway) resolvePolicy(version string) (Policy, bool) {
	if version == "" {
		return g.archive.Latest()
	}
	return g.archive.Get(version)
}

// subjectNote 汇总单个主体的可读说明（拒绝原因/降级细节）
func (g *Gateway) subjectNote(resp AccessResponse) string {
	if !resp.Decision.Allowed {
		return "访问被拒绝：" + string(resp.Decision.Reason) + "；依据：" + resp.Decision.Basis
	}
	if len(resp.Skipped) > 0 {
		return "放行但降级：跳过字段 " + joinFieldNames(resp.Skipped)
	}
	return "放行"
}

// writeBatchHead 写一条批次汇总审计记录，把整批输入、口径与每个主体结论关联起来
func (g *Gateway) writeBatchHead(batchID string, req BatchRequest, resp BatchResponse,
	evaluatedAt time.Time, version string, n int) {

	status := OutcomeStatus("")
	note := ""
	if resp.Rejected {
		status = StatusDenied
		note = "批次被整体拒绝：" + string(resp.Reason) + "；" + resp.Message
	} else {
		status = StatusAllowed
		note = "批次完成：共 " + itoa(n) +
			" 人，放行 " + itoa(resp.Summary.Allowed) +
			"，拒绝 " + itoa(resp.Summary.Denied) +
			"，降级 " + itoa(resp.Summary.Degraded) +
			"；口径：判断时刻 " + evaluatedAt.Format(time.RFC3339) +
			"，策略版本 " + version
	}
	g.audit.Append(AuditRecord{
		Timestamp:     evaluatedAt,
		Entry:         req.Entry,
		Purpose:       req.Purpose,
		Category:      req.Category,
		Requested:     req.Fields,
		PolicyVersion: version,
		Note:          note,
		BatchID:       batchID,
		IsBatchHead:   true,
		SubjectIndex:  -1,
		Outcome:       status,
	})
}

func cloneRecord(r Record) Record {
	if r == nil {
		return nil
	}
	cp := make(Record, len(r))
	for k, v := range r {
		cp[k] = v
	}
	return cp
}

func cloneBatchResponse(r BatchResponse) BatchResponse {
	cp := r
	if r.Outcomes != nil {
		cp.Outcomes = make([]SubjectOutcome, len(r.Outcomes))
		copy(cp.Outcomes, r.Outcomes)
		for i := range cp.Outcomes {
			cp.Outcomes[i].Record = cloneRecord(r.Outcomes[i].Record)
		}
	}
	return cp
}

func joinFieldNames(fs []FieldName) string {
	out := ""
	for i, f := range fs {
		if i > 0 {
			out += ","
		}
		out += string(f)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// 数据层拒绝原因：这些分支的结论由当时本地数据决定，回放时不重新读取数据，
// 直接以历史审计记录为准（历史记录是唯一事实来源）。
var dataLayerReasons = map[DenyReason]bool{
	ReasonRecordNotFound:      true,
	ReasonFieldsNotAuthorized: true,
	ReasonMinimizationFailed:  true,
}

// ReplayBatch 按批次 ID 还原当时整批结果：
// 每个主体的状态、返回字段范围、拒绝/降级原因全部取自历史审计记录，
// 再按记录标注的策略版本与判断时刻重跑同意判定做交叉校验；
// 结论不会被现在变化的同意状态或策略影响。
func (g *Gateway) ReplayBatch(batchID string) (BatchReplay, bool) {
	recs := g.audit.ListByBatch(batchID)
	var head AuditRecord
	var subjectRecs []AuditRecord
	for _, r := range recs {
		if r.IsBatchHead {
			head = r
			continue
		}
		subjectRecs = append(subjectRecs, r)
	}
	if head.BatchID == "" {
		return BatchReplay{BatchID: batchID}, false
	}

	// 按历史稳定下标排序，防止并发写入顺序造成错配
	sortByIndex(subjectRecs)

	subjects := make([]SubjectReplay, 0, len(subjectRecs))
	allMatch := true
	for _, r := range subjectRecs {
		sr := SubjectReplay{
			Index:          r.SubjectIndex,
			Subject:        r.SubjectID,
			Status:         r.Outcome,
			Recorded:       r.Decision,
			FieldsReturned: append([]FieldName(nil), r.FieldsReturned...),
			Note:           r.Note,
		}
		if dataLayerReasons[r.Decision.Reason] {
			// 数据层结论以历史记录为准，不再重新读取当前数据
			sr.RecheckMatches = true
		} else {
			sr.ConsentRecheck = g.recheck(r)
			sr.RecheckMatches = sr.ConsentRecheck.Allowed == r.Decision.Allowed &&
				sr.ConsentRecheck.Reason == r.Decision.Reason &&
				sr.ConsentRecheck.PolicyVersion == r.PolicyVersion
		}
		if !sr.RecheckMatches {
			allMatch = false
		}
		subjects = append(subjects, sr)
	}

	return BatchReplay{
		BatchID:       batchID,
		Found:         true,
		Purpose:       head.Purpose,
		Category:      head.Category,
		PolicyVersion: head.PolicyVersion,
		EvaluatedAt:   head.Timestamp,
		Subjects:      subjects,
		AllMatch:      allMatch,
	}, true
}

// sortByIndex 按 SubjectIndex 升序排列主体审计记录（插入排序，n 有上限）
func sortByIndex(recs []AuditRecord) {
	for i := 1; i < len(recs); i++ {
		for j := i; j > 0 && recs[j-1].SubjectIndex > recs[j].SubjectIndex; j-- {
			recs[j-1], recs[j] = recs[j], recs[j-1]
		}
	}
}

// OutcomeStatus 批次内单个主体的最终结论
type OutcomeStatus string

const (
	// StatusAllowed 完整放行
	StatusAllowed OutcomeStatus = "allowed"
	// StatusDenied 拒绝（同意层或数据层），不返回数据
	StatusDenied OutcomeStatus = "denied"
	// StatusDegraded 放行但发生字段级降级（部分字段被跳过）
	StatusDegraded OutcomeStatus = "degraded"
)

// 批次级拒绝原因（在 DenyReason 命名空间内，保持可区分）
const (
	// ReasonBatchEmpty 批次没有任何主体
	ReasonBatchEmpty DenyReason = "batch_empty"
	// ReasonBatchTooLarge 批次主体数超过 MaxBatchSubjects
	ReasonBatchTooLarge DenyReason = "batch_too_large"
	// ReasonBatchDuplicateSubject 同一批次内出现重复主体
	ReasonBatchDuplicateSubject DenyReason = "batch_duplicate_subject"
)

// BatchRequest 批量访问请求：同一用途、同一数据类别、同一字段集合，面向多个数据主体
type BatchRequest struct {
	Entry string
	// IdempotencyKey 幂等键：相同键的重试/断点重跑返回首次结论，不重复处理与审计
	IdempotencyKey string
	Purpose        Purpose
	Category       Category
	Fields         []FieldName
	// Version 为空时整批固定按提交时刻的最新版本判定
	Version  string
	Subjects []SubjectID
}

// SubjectOutcome 批次内单个主体的独立结论
type SubjectOutcome struct {
	Index    int // 该主体在请求中的稳定下标（从 0 开始）
	Subject  SubjectID
	Status   OutcomeStatus
	Decision Decision
	AuditID  int64  // 该主体独立审计记录的 ID
	Record   Record // 最小化+脱敏后的该主体数据；拒绝时为 nil
	Note     string
}

// BatchSummary 整批汇总计数
type BatchSummary struct {
	Total    int
	Allowed  int
	Denied   int
	Degraded int
}

// BatchResponse 批量访问结果
type BatchResponse struct {
	BatchID string
	// Rejected 为 true 表示批次在入口校验阶段被整体拒绝（未处理任何主体）
	Rejected      bool
	Reason        DenyReason
	Message       string
	Purpose       Purpose
	Category      Category
	PolicyVersion string           // 整批固定使用的策略版本
	EvaluatedAt   time.Time        // 整批固定使用的判断时刻
	Outcomes      []SubjectOutcome // 与请求主体顺序严格一致
	Summary       BatchSummary
}

// SubjectReplay 单个主体的历史回放结论
type SubjectReplay struct {
	Index          int
	Subject        SubjectID
	Status         OutcomeStatus // 按历史审计记录还原的状态
	Recorded       Decision      // 历史审计记录中的最终结论
	ConsentRecheck Decision      // 按记录标注的版本与判断时刻重新执行的同意判定
	FieldsReturned []FieldName   // 历史实际返回字段范围
	Note           string
	// RecheckMatches 重新执行的同意判定是否与历史同意层结论一致
	RecheckMatches bool
}

// BatchReplay 整批历史回放结果
type BatchReplay struct {
	BatchID       string
	Found         bool
	Purpose       Purpose
	Category      Category
	PolicyVersion string
	EvaluatedAt   time.Time
	Subjects      []SubjectReplay
	AllMatch      bool
}
