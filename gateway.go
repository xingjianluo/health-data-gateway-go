package gateway

import "time"

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
	}
}

// Access 统一访问入口。无论允许还是拒绝，都会写入一条标注策略版本的审计记录。
func (g *Gateway) Access(req AccessRequest) AccessResponse {
	// 1. 同意校验（可按显式版本或最新版本判定）
	dec := g.decider.Decide(req.Subject, req.Purpose, req.Category, req.Version)

	auditRec := AuditRecord{
		Timestamp:     g.clock(),
		Entry:         req.Entry,
		SubjectID:     req.Subject,
		Purpose:       req.Purpose,
		Category:      req.Category,
		Requested:     req.Fields,
		Decision:      dec,
		PolicyVersion: dec.PolicyVersion,
	}

	if !dec.Allowed {
		auditRec.Note = "访问被拒绝：" + string(dec.Reason) + "；依据：" + dec.Basis
		saved := g.audit.Append(auditRec)
		return AccessResponse{AuditID: saved.ID, Decision: dec}
	}

	// 2. 读取本地原始数据
	pol, _ := g.archive.Get(dec.PolicyVersion)
	rec, ok := g.store.Get(req.Subject, req.Category)
	if !ok {
		dec.Allowed = false
		dec.Reason = ReasonRecordNotFound
		dec.Basis = "本地存储中不存在主体 " + string(req.Subject) + " 的类别 " + string(req.Category) + " 数据"
		auditRec.Decision = dec
		auditRec.Note = "访问被拒绝：本地无对应数据"
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
		saved := g.audit.Append(auditRec)
		return AccessResponse{AuditID: saved.ID, Decision: dec}
	}

	// 4. 最小化 + 脱敏
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
		saved := g.audit.Append(auditRec)
		return AccessResponse{AuditID: saved.ID, Decision: dec}
	}

	auditRec.FieldsReturned = fieldNames(result.Record)
	auditRec.Note = joinNotes(result.Notes)
	saved := g.audit.Append(auditRec)
	return AccessResponse{AuditID: saved.ID, Decision: dec, Record: result.Record}
}

// Replay 按审计记录当时标注的策略版本复现历史授权结论。
func (g *Gateway) Replay(auditID int64) (Decision, bool) {
	rec, ok := g.audit.Get(auditID)
	if !ok {
		return Decision{}, false
	}
	// 使用记录中标注的版本，而非当前最新版本，保证结论可复现
	redone := g.decider.Decide(rec.SubjectID, rec.Purpose, rec.Category, rec.PolicyVersion)
	return redone, true
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
