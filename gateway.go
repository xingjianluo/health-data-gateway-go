package gateway

import (
	"fmt"
	"sync"
	"time"
)

// AccessRequest 统一的访问请求（任意访问入口共用）
type AccessRequest struct {
	Entry    string // 访问入口名（如 clinical / research）
	Subject  SubjectID
	Purpose  Purpose
	Category Category
	Fields   []FieldName // 调用方希望读取的字段
	// Version 为空表示按最新策略版本判定
	Version string
}

// AccessResponse 访问结果
type AccessResponse struct {
	AuditID  int64
	Decision Decision
	Record   Record // 最小化+脱敏后的字段；拒绝时为 nil
	// Skipped 降级模式下被跳过的授权字段；非空表示该次访问发生了字段级降级
	Skipped []FieldName
}

// batchCtx 批量访问附加到单主体处理流程上的固定上下文。
// 零值表示这是一次普通单主体访问。
type batchCtx struct {
	batchID      string
	subjectIndex int
	evaluatedAt  time.Time // 整批固定的判断时刻
	version      string    // 整批固定的策略版本
}

// DegradeMode 脱敏/最小化失败时的处理策略
type DegradeMode int

const (
	// DegradeDeny fail-closed：脱敏失败或字段缺失即拒绝（默认）
	DegradeDeny DegradeMode = iota
	// DegradeSkip 降级：跳过问题字段，其余照常返回，跳过细节写入审计
	DegradeSkip
)

// Gateway 健康数据访问网关：串联同意校验、最小化脱敏、审计
type Gateway struct {
	archive *PolicyArchive
	store   *HealthStore
	audit   *AuditLog
	decider *Decider
	masker  *Minimizer
	clock   func() time.Time
	Degrade DegradeMode

	batchMu  sync.Mutex
	batchSeq int64
	idem     *idempotencyRegistry
}

func New(archive *PolicyArchive, store *HealthStore, audit *AuditLog) *Gateway {
	return &Gateway{
		archive: archive,
		store:   store,
		audit:   audit,
		decider: NewDecider(archive),
		masker:  NewMinimizer(),
		clock:   time.Now,
		Degrade: DegradeDeny,
		idem:    newIdempotencyRegistry(),
	}
}

// newBatchID 分配进程内唯一批次 ID（锁内自增，并发下不重复、不串位）
func (g *Gateway) newBatchID() string {
	g.batchMu.Lock()
	defer g.batchMu.Unlock()
	g.batchSeq++
	return fmt.Sprintf("batch-%06d", g.batchSeq)
}

// Access 统一访问入口。无论允许还是拒绝，都会写入一条标注策略版本的审计记录。
func (g *Gateway) Access(req AccessRequest) AccessResponse {
	return g.access(req, g.clock(), batchCtx{})
}

// access 单主体流水线。evaluatedAt 为本次判断时刻（批量时整批共用同一时刻）；
// bc 非零时，审计记录带批次 ID、主体下标与整批状态，用于整批关联与回放。
func (g *Gateway) access(req AccessRequest, evaluatedAt time.Time, bc batchCtx) AccessResponse {
	// 1. 同意校验（可按显式版本或最新版本判定；批量时版本已在批次入口固定）
	dec := g.decider.DecideAt(req.Subject, req.Purpose, req.Category, req.Version, evaluatedAt)

	auditRec := AuditRecord{
		Timestamp:     evaluatedAt,
		Entry:         req.Entry,
		SubjectID:     req.Subject,
		Purpose:       req.Purpose,
		Category:      req.Category,
		Requested:     req.Fields,
		Decision:      dec,
		PolicyVersion: dec.PolicyVersion,
	}
	attachBatch(&auditRec, bc, dec, nil)

	if !dec.Allowed {
		auditRec.Note = "访问被拒绝：" + string(dec.Reason) + "；依据：" + dec.Basis
		saved := g.audit.Append(auditRec)
		return AccessResponse{AuditID: saved.ID, Decision: dec}
	}

	// 2. 读取本地原始数据（每人独立读取，结果互不串用）
	pol, _ := g.archive.Get(dec.PolicyVersion)
	rec, ok := g.store.Get(req.Subject, req.Category)
	if !ok {
		dec.Allowed = false
		dec.Reason = ReasonRecordNotFound
		dec.Basis = "本地存储中不存在主体 " + string(req.Subject) + " 的类别 " + string(req.Category) + " 数据"
		auditRec.Decision = dec
		auditRec.Note = "访问被拒绝：本地无对应数据"
		attachBatch(&auditRec, bc, dec, nil)
		saved := g.audit.Append(auditRec)
		return AccessResponse{AuditID: saved.ID, Decision: dec}
	}

	// 3. 字段授权取交集：请求字段 ∩ 同意白名单，保证结果不超出授权范围
	allowedFields := intersectFields(req.Fields, consentFields(pol, req.Subject))
	if len(req.Fields) > 0 && len(allowedFields) == 0 {
		dec.Allowed = false
		dec.Reason = ReasonFieldsNotAuthorized
		dec.Basis = "请求的字段均不在同意白名单内"
		auditRec.Decision = dec
		auditRec.Note = "访问被拒绝：字段授权交集为空"
		attachBatch(&auditRec, bc, dec, nil)
		saved := g.audit.Append(auditRec)
		return AccessResponse{AuditID: saved.ID, Decision: dec}
	}

	// 4. 最小化 + 脱敏（每人独立执行，一个人的失败不影响其他人）
	var result MinimizeResult
	var maskErr error
	if g.Degrade == DegradeSkip {
		result = g.masker.DegradeApply(rec, allowedFields, pol.Identifiers, pol.Masking)
	} else {
		result, maskErr = g.masker.Apply(rec, allowedFields, pol.Identifiers, pol.Masking)
	}

	if maskErr != nil {
		// fail-closed：不返回任何原始数据
		dec.Allowed = false
		dec.Reason = ReasonMinimizationFailed
		dec.Basis = "最小化/脱敏失败，已拒绝返回原始数据：" + maskErr.Error()
		auditRec.Decision = dec
		auditRec.Note = dec.Basis
		attachBatch(&auditRec, bc, dec, nil)
		saved := g.audit.Append(auditRec)
		return AccessResponse{AuditID: saved.ID, Decision: dec}
	}

	auditRec.FieldsReturned = fieldNames(result.Record)
	auditRec.Note = joinNotes(result.Notes)
	attachBatch(&auditRec, bc, dec, result.Skipped)
	saved := g.audit.Append(auditRec)
	return AccessResponse{
		AuditID:  saved.ID,
		Decision: dec,
		Record:   result.Record,
		Skipped:  append([]FieldName(nil), result.Skipped...),
	}
}

// attachBatch 在写入审计前补齐批量关联信息（非批量上下文为空操作）
func attachBatch(rec *AuditRecord, bc batchCtx, dec Decision, skipped []FieldName) {
	if bc.batchID == "" {
		return
	}
	rec.BatchID = bc.batchID
	rec.SubjectIndex = bc.subjectIndex
	rec.Outcome = outcomeOf(dec, skipped)
}

// Replay 按审计记录当时标注的策略版本和判断时刻复现历史授权结论。
func (g *Gateway) Replay(auditID int64) (Decision, bool) {
	rec, ok := g.audit.Get(auditID)
	if !ok {
		return Decision{}, false
	}
	// 使用记录中标注的版本与当时的判断时刻，而非当前最新版本/当前时刻，保证结论可复现
	redone := g.recheck(rec)
	return redone, true
}

// recheck 按审计记录标注的策略版本与判断时刻重新执行同意判定
func (g *Gateway) recheck(rec AuditRecord) Decision {
	return g.decider.DecideAt(rec.SubjectID, rec.Purpose, rec.Category,
		rec.PolicyVersion, rec.Decision.EvaluatedAt)
}

// outcomeOf 根据最终决策与降级字段推导主体状态
func outcomeOf(dec Decision, skipped []FieldName) OutcomeStatus {
	if !dec.Allowed {
		return StatusDenied
	}
	if len(skipped) > 0 {
		return StatusDegraded
	}
	return StatusAllowed
}

func consentFields(pol Policy, subject SubjectID) []FieldName {
	c, ok := pol.Consents[subject]
	if !ok {
		return nil
	}
	return c.Fields
}

func intersectFields(requested, authorized []FieldName) []FieldName {
	if len(requested) == 0 {
		// 未显式指定字段时，按白名单整体最小化
		return append([]FieldName(nil), authorized...)
	}
	authSet := make(map[FieldName]bool, len(authorized))
	for _, f := range authorized {
		authSet[f] = true
	}
	var out []FieldName
	seen := make(map[FieldName]bool)
	for _, f := range requested {
		if authSet[f] && !seen[f] {
			out = append(out, f)
			seen[f] = true
		}
	}
	return out
}

func fieldNames(rec Record) []FieldName {
	out := make([]FieldName, 0, len(rec))
	for k := range rec {
		out = append(out, k)
	}
	return out
}

func joinNotes(notes []string) string {
	out := ""
	for i, n := range notes {
		if i > 0 {
			out += "；"
		}
		out += n
	}
	return out
}
