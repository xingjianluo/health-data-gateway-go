package gateway

import (
	"strconv"
	"sync"
	"time"
)

// 本文件在既有单主体访问能力之上增加“批量访问”一层：
// 同一访问用途、同一数据类型下对多个数据主体发起访问，
// 每个主体独立判定、独立最小化与脱敏，互不拖垮、互不串数据。

// MaxBatchSubjects 单批数据主体数量上限（默认值，可被 Gateway.BatchLimit 覆盖）
const MaxBatchSubjects = 100

// BatchStatus 整批结论
type BatchStatus string

const (
	// BatchProcessed 整批已处理：每个主体都有独立结论（可能全部/部分放行，也可能全部拒绝）
	BatchProcessed BatchStatus = "processed"
	// BatchRejected 整批在处理前被拒绝（如超过批量上限、主体列表为空），不读取任何主体数据
	BatchRejected BatchStatus = "rejected"
)

// SubjectStatus 批次内单个主体的结论
type SubjectStatus string

const (
	// SubjectAllowed 放行：字段完整返回
	SubjectAllowed SubjectStatus = "allowed"
	// SubjectDegraded 降级放行：有字段被跳过，但仍返回了该主体的数据
	SubjectDegraded SubjectStatus = "degraded"
	// SubjectDenied 拒绝：不返回该主体任何数据
	SubjectDenied SubjectStatus = "denied"
)

// 整批被拒绝的可区分原因（单主体拒绝原因仍使用 decision.go 中的 DenyReason）
const (
	ReasonBatchTooLarge DenyReason = "batch_too_large"
	ReasonBatchEmpty    DenyReason = "batch_empty"
)

// BatchRequest 一次批量访问请求：全批共用同一入口、用途、类别、字段与策略版本
type BatchRequest struct {
	Entry    string
	Subjects []SubjectID
	Purpose  Purpose
	Category Category
	Fields   []FieldName
	// Version 为空表示按批次提交时刻的最新策略版本判定；
	// 一旦批次开始处理，全批固定使用同一版本，中途不换口径。
	Version string
	// IdempotencyKey 调用方提供的幂等键；同一键的重试/断点重跑返回同一结论，
	// 不重复读取、不重复写审计。
	IdempotencyKey string
}

// SubjectResult 批次内单个主体的独立结论
type SubjectResult struct {
	Subject  SubjectID
	Status   SubjectStatus
	Decision Decision // 该主体自己的判定结论（允许/拒绝、原因、依据、策略版本、判定时刻）
	Record   Record   // 该主体独立最小化+脱敏后的记录；拒绝时为 nil
	// AuditID 该主体对应的逐条审计记录 ID
	AuditID int64
}

// BatchResponse 整批结果：主体顺序与去重后的请求顺序保持稳定一致
type BatchResponse struct {
	// BatchID 整批审计记录 ID
	BatchID int64
	Status  BatchStatus
	// Reason / Basis 整批被拒绝时的原因与依据
	Reason DenyReason
	Basis  string

	// 全批统一口径
	PolicyVersion string
	EvaluatedAt   time.Time

	// Results 稳定的主体顺序结果
	Results []SubjectResult

	// 整批汇总
	Total    int
	Allowed  int
	Degraded int
	Denied   int

	// Cached=true 表示本次返回来自幂等缓存（重试未重新读取/重复审计）
	Cached bool
	Note   string
}

// batchConcurrency 单批内逐主体处理的本地并发度上限
const batchConcurrency = 16

// AccessBatch 批量访问入口。
//
// 口径保证：
//   - 批次提交时刻固定唯一判定时刻与策略版本，全批共用，处理中途不换口径；
//   - 每个主体独立判定、独立读取、独立最小化脱敏，一个人被拒绝/降级/字段缺失
//     不影响其他人，也不会把 A 的数据放进 B 的结果（结果按索引槽位写回）；
//   - 幂等：同一 IdempotencyKey 的重试/并发同键/断点重跑只执行一次，
//     返回同一份结论，不重复读取、不重复写逐条审计、不产生第二条整批记录；
//   - 容量：去重后主体数超过上限或为 0 时整批明确拒绝，不读取任何主体数据；
//   - 主体顺序：按去重后的首次出现顺序稳定返回。
func (g *Gateway) AccessBatch(req BatchRequest) BatchResponse {
	// 1. 幂等登记（同键并发时只有一个调用方真正执行，其余等待并复用结论）
	batchID, wait, execute := g.batches.Claim(req.IdempotencyKey)
	if !execute {
		<-wait
		if saved, ok := g.batches.GetByKey(req.IdempotencyKey); ok {
			resp := batchRecordToResponse(saved)
			resp.Cached = true
			return resp
		}
		// 理论不可达：channel 关闭时一定已 Commit
		return BatchResponse{BatchID: batchID, Status: BatchRejected, Reason: ReasonBatchEmpty}
	}

	// 2. 去重保序（重复主体只处理一次，顺序取首次出现位置）
	subjects := dedupSubjects(req.Subjects)

	limit := g.BatchLimit
	if limit <= 0 {
		limit = MaxBatchSubjects
	}

	// 3. 容量校验（整批拒绝路径：不读取数据、不产生逐条审计，仅落整批记录）
	if len(subjects) == 0 {
		return g.rejectBatch(req, batchID, subjects,
			ReasonBatchEmpty, "批量访问被拒绝：主体列表为空")
	}
	if len(subjects) > limit {
		return g.rejectBatch(req, batchID, subjects, ReasonBatchTooLarge,
			"批量访问被拒绝：去重后主体数 "+strconv.Itoa(len(subjects))+
				" 超过单批上限 "+strconv.Itoa(limit))
	}

	// 4. 全批固定口径：此刻解析一次策略版本与判定时刻，之后整批不再变化
	evaluatedAt := g.clock()
	pol, ver, hasPolicy := g.resolvePolicy(req.Version, evaluatedAt)

	// 5. 逐主体独立处理（有界并发，结果按索引槽位写回，绝不串位）
	results := make([]SubjectResult, len(subjects))
	sem := make(chan struct{}, batchConcurrency)
	var wg sync.WaitGroup
	for i, subj := range subjects {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, subj SubjectID) {
			defer wg.Done()
			defer func() { <-sem }()
			resp := g.processSubject(subj, req.Purpose, req.Category, req.Fields,
				req.Entry, ver, evaluatedAt, hasPolicy, pol, batchID)
			results[i] = SubjectResult{
				Subject:  subj,
				Status:   subjectStatusOf(resp),
				Decision: resp.Decision,
				Record:   resp.Record,
				AuditID:  resp.AuditID,
			}
		}(i, subj)
	}
	wg.Wait()

	// 6. 整批汇总（顺序与 subjects 一致）
	rec := BatchRecord{
		BatchID:        batchID,
		IdempotencyKey: req.IdempotencyKey,
		Timestamp:      evaluatedAt,
		Entry:          req.Entry,
		Purpose:        req.Purpose,
		Category:       req.Category,
		Requested:      append([]FieldName(nil), req.Fields...),
		PolicyVersion:  ver,
		EvaluatedAt:    evaluatedAt,
		Status:         BatchProcessed,
		Results:        make([]BatchSubjectRecord, len(results)),
		Note:           batchDedupNote(req.Subjects, subjects),
	}
	for i, r := range results {
		rec.Results[i] = BatchSubjectRecord{
			Subject:  r.Subject,
			Status:   r.Status,
			Decision: r.Decision,
			Record:   cloneRecord(r.Record),
			AuditID:  r.AuditID,
		}
		switch r.Status {
		case SubjectAllowed:
			rec.Allowed++
		case SubjectDegraded:
			rec.Degraded++
		default:
			rec.Denied++
		}
	}
	rec.Total = len(results)

	// 7. 提交不可变整批快照（同时放行等待同键结果的重试方）
	g.batches.Commit(rec)
	return batchRecordToResponse(g.mustGetBatch(batchID))
}

// rejectBatch 处理整批被拒绝（空列表/超上限）：只落整批审计，不读取、不写逐条审计
func (g *Gateway) rejectBatch(req BatchRequest, batchID int64, subjects []SubjectID,
	reason DenyReason, basis string) BatchResponse {
	now := g.clock()
	rec := BatchRecord{
		BatchID:        batchID,
		IdempotencyKey: req.IdempotencyKey,
		Timestamp:      now,
		Entry:          req.Entry,
		Purpose:        req.Purpose,
		Category:       req.Category,
		Requested:      append([]FieldName(nil), req.Fields...),
		EvaluatedAt:    now,
		Status:         BatchRejected,
		Reason:         reason,
		Basis:          basis,
		Total:          len(subjects),
		Note:           batchDedupNote(req.Subjects, subjects),
	}
	g.batches.Commit(rec)
	saved := g.mustGetBatch(batchID)
	resp := batchRecordToResponse(saved)
	return resp
}

func (g *Gateway) mustGetBatch(id int64) BatchRecord {
	rec, ok := g.batches.Get(id)
	if !ok {
		// Commit 后立即可读；不可达，保守返回空壳避免崩溃
		return BatchRecord{BatchID: id}
	}
	return rec
}

func subjectStatusOf(r AccessResponse) SubjectStatus {
	switch {
	case !r.Decision.Allowed:
		return SubjectDenied
	case r.Degraded:
		return SubjectDegraded
	default:
		return SubjectAllowed
	}
}

// dedupSubjects 按首次出现顺序去重，保证返回主体顺序稳定
func dedupSubjects(in []SubjectID) []SubjectID {
	seen := make(map[SubjectID]bool, len(in))
	out := make([]SubjectID, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func batchDedupNote(raw, deduped []SubjectID) string {
	if len(raw) == len(deduped) {
		return ""
	}
	return "请求主体 " + strconv.Itoa(len(raw)) + " 个，去重/忽略空标识后实际处理 " + strconv.Itoa(len(deduped)) + " 个"
}

func batchRecordToResponse(r BatchRecord) BatchResponse {
	resp := BatchResponse{
		BatchID:       r.BatchID,
		Status:        r.Status,
		Reason:        r.Reason,
		Basis:         r.Basis,
		PolicyVersion: r.PolicyVersion,
		EvaluatedAt:   r.EvaluatedAt,
		Results:       nil,
		Total:         r.Total,
		Allowed:       r.Allowed,
		Degraded:      r.Degraded,
		Denied:        r.Denied,
		Note:          r.Note,
	}
	if r.Results != nil {
		resp.Results = make([]SubjectResult, len(r.Results))
		for i, s := range r.Results {
			resp.Results[i] = SubjectResult{
				Subject:  s.Subject,
				Status:   s.Status,
				Decision: s.Decision,
				Record:   cloneRecord(s.Record),
				AuditID:  s.AuditID,
			}
		}
	}
	return resp
}

// BatchSubjectRecord 整批快照中单个主体的落盘记录
type BatchSubjectRecord struct {
	Subject  SubjectID
	Status   SubjectStatus
	Decision Decision
	Record   Record // 当时实际返回范围（拒绝为 nil）
	AuditID  int64
}

// BatchRecord 一次批量访问的完整不可变审计快照，也是历史回放的依据
type BatchRecord struct {
	BatchID        int64
	IdempotencyKey string
	Timestamp      time.Time
	Entry          string
	Purpose        Purpose
	Category       Category
	Requested      []FieldName
	PolicyVersion  string
	EvaluatedAt    time.Time

	Status BatchStatus
	Reason DenyReason
	Basis  string

	Results []BatchSubjectRecord

	Total    int
	Allowed  int
	Degraded int
	Denied   int
	Note     string
}

// ReplayBatch 按整批审计记录回放历史批次。
// 回放只依据当时落盘的不可变整批快照，还原当时的整批结论——
// 包括部分成功、每个人的拒绝/降级原因与实际返回范围，
// 不受当前同意状态（撤回、过期）或当前最新策略版本变化影响。
func (g *Gateway) ReplayBatch(batchID int64) (BatchResponse, bool) {
	rec, ok := g.batches.Get(batchID)
	if !ok {
		return BatchResponse{}, false
	}
	return batchRecordToResponse(rec), true
}
