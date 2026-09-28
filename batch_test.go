package gateway

import (
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"
)

const (
	subjCarol SubjectID = "carol"
	subjDave  SubjectID = "dave"
	subjErin  SubjectID = "erin"
	subjFrank SubjectID = "frank"
)

// newBatchFixture 构造批量场景：
//   - alice：同意有效，数据齐全（放行，姓名抹除/手机号局部脱敏）
//   - bob：策略中无任何同意记录（consent_missing，拒绝，且不会读其数据）
//   - carol：同意已撤回（consent_withdrawn，拒绝）
//   - dave：同意有效但记录缺 heart_rate（DegradeSkip 下降级放行）
//   - erin：只授权 research 用途（purpose_out_of_scope，拒绝）
//   - frank：同意有效，数据齐全但数值与 alice 不同（用于验证主体间不串数据）
func newBatchFixture(t *testing.T, now time.Time) *Gateway {
	t.Helper()
	consent := func(subject SubjectID, purposes []Purpose, withdrawn bool) Consent {
		return Consent{
			SubjectID:  subject,
			Purposes:   purposes,
			Categories: []Category{catVitals},
			Fields:     []FieldName{fieldName, fieldPhone, fieldHeart},
			GrantedAt:  now.Add(-time.Hour),
			Withdrawn:  withdrawn,
		}
	}
	pol := Policy{
		Version: "vBatch",
		Consents: map[SubjectID]Consent{
			subjAlice: consent(subjAlice, []Purpose{purposeTreatment}, false),
			subjCarol: consent(subjCarol, []Purpose{purposeTreatment}, true),
			subjDave:  consent(subjDave, []Purpose{purposeTreatment}, false),
			subjErin:  consent(subjErin, []Purpose{purposeResearch}, false),
			subjFrank: consent(subjFrank, []Purpose{purposeTreatment}, false),
		},
		Identifiers: []FieldName{fieldName, fieldPhone},
		Masking: map[FieldName]MaskingRule{
			fieldName:  {Field: fieldName, Action: MaskRedact},
			fieldPhone: {Field: fieldPhone, Action: MaskPartial},
		},
		CreatedAt: now,
	}
	archive := NewPolicyArchive()
	archive.Put(pol)

	store := NewHealthStore()
	store.Put(subjAlice, catVitals, Record{
		fieldName: "Alice Wang", fieldPhone: "13812345678", fieldHeart: "72",
	})
	// dave 缺 heart_rate：降级模式下应跳过该字段
	store.Put(subjDave, catVitals, Record{
		fieldName: "Dave Li", fieldPhone: "13611112222",
	})
	store.Put(subjFrank, catVitals, Record{
		fieldName: "Frank Yu", fieldPhone: "13987654321", fieldHeart: "88",
	})

	audit := NewAuditLog()
	g := New(archive, store, audit)
	g.Degrade = DegradeSkip
	g.clock = func() time.Time { return now }
	g.decider.clock = func() time.Time { return now }
	return g
}

func logBatchResponse(t *testing.T, resp BatchResponse) {
	t.Helper()
	t.Logf("【整批】batchID=%d status=%s reason=%q version=%s evaluatedAt=%s 汇总 total=%d allowed=%d degraded=%d denied=%d cached=%v note=%s",
		resp.BatchID, resp.Status, string(resp.Reason), resp.PolicyVersion,
		resp.EvaluatedAt.Format(time.RFC3339), resp.Total, resp.Allowed, resp.Degraded, resp.Denied, resp.Cached, resp.Note)
	for _, r := range resp.Results {
		t.Logf("【主体】%s status=%s reason=%q auditID=%d\n【依据】%s\n【输出】%v",
			r.Subject, r.Status, string(r.Decision.Reason), r.AuditID, r.Decision.Basis, r.Record)
	}
}

// TestBatchMixedResults 混合批次：批次内主体状态各不相同，
// 独立判定/独立最小化脱敏、顺序稳定、互不拖垮互不串数据、汇总与逐条审计关联正确。
func TestBatchMixedResults(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g := newBatchFixture(t, now)

	// 故意打乱顺序，并夹带重复主体与空标识，验证去重保序
	req := BatchRequest{
		Entry: "ward-round",
		// 期望去重保序后：erin, alice, frank, bob, dave, carol
		Subjects: []SubjectID{subjErin, subjAlice, subjFrank, subjBob, subjAlice, "", subjDave, subjCarol},
		Purpose:  purposeTreatment,
		Category: catVitals,
		Fields:   []FieldName{fieldName, fieldPhone, fieldHeart},
		Version:  "vBatch",
	}
	logTestInput(t, "批量请求 entry=%s subjects=%v purpose=%s category=%s fields=%v version=%s",
		req.Entry, req.Subjects, req.Purpose, req.Category, req.Fields, req.Version)

	resp := g.AccessBatch(req)
	logBatchResponse(t, resp)

	if resp.Status != BatchProcessed {
		t.Fatalf("混合批次应处理, got=%s basis=%s", resp.Status, resp.Basis)
	}
	wantOrder := []SubjectID{subjErin, subjAlice, subjFrank, subjBob, subjDave, subjCarol}
	gotOrder := make([]SubjectID, len(resp.Results))
	for i, r := range resp.Results {
		gotOrder[i] = r.Subject
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("主体顺序不稳定：got=%v want=%v", gotOrder, wantOrder)
	}
	if resp.Total != 6 || resp.Allowed != 2 || resp.Degraded != 1 || resp.Denied != 3 {
		t.Fatalf("整批汇总错误：total=%d allowed=%d degraded=%d denied=%d",
			resp.Total, resp.Allowed, resp.Degraded, resp.Denied)
	}

	wantStatus := map[SubjectID]SubjectStatus{
		subjAlice: SubjectAllowed,
		subjFrank: SubjectAllowed,
		subjDave:  SubjectDegraded,
		subjBob:   SubjectDenied,
		subjCarol: SubjectDenied,
		subjErin:  SubjectDenied,
	}
	wantReason := map[SubjectID]DenyReason{
		subjBob:   ReasonConsentMissing,
		subjCarol: ReasonConsentWithdrawn,
		subjErin:  ReasonPurposeOutOfScope,
	}
	for _, r := range resp.Results {
		if r.Status != wantStatus[r.Subject] {
			t.Fatalf("主体 %s 状态错误：got=%s", r.Subject, r.Status)
		}
		if r.Status == SubjectDenied {
			if r.Record != nil {
				t.Fatalf("被拒绝主体 %s 不得返回数据", r.Subject)
			}
			if r.Decision.Reason != wantReason[r.Subject] {
				t.Fatalf("主体 %s 拒绝原因错误：got=%s", r.Subject, r.Decision.Reason)
			}
		}
		if r.Decision.PolicyVersion != "vBatch" || !r.Decision.EvaluatedAt.Equal(now) {
			t.Fatalf("主体 %s 口径未统一：version=%s at=%s", r.Subject, r.Decision.PolicyVersion, r.Decision.EvaluatedAt)
		}
	}

	// 数据不串位：alice 与 frank 数值各不相同，脱敏各自生效
	bySubj := map[SubjectID]SubjectResult{}
	for _, r := range resp.Results {
		bySubj[r.Subject] = r
	}
	if bySubj[subjAlice].Record[fieldHeart] != "72" || bySubj[subjFrank].Record[fieldHeart] != "88" {
		t.Fatalf("主体数据串位：alice=%v frank=%v", bySubj[subjAlice].Record, bySubj[subjFrank].Record)
	}
	if bySubj[subjAlice].Record[fieldName] != "***REDACTED***" ||
		bySubj[subjFrank].Record[fieldPhone] == "13987654321" {
		t.Fatalf("脱敏未按各主体独立执行：alice=%v frank=%v",
			bySubj[subjAlice].Record, bySubj[subjFrank].Record)
	}
	// dave 降级：heart_rate 缺失被跳过，其余字段返回
	if _, has := bySubj[subjDave].Record[fieldHeart]; has {
		t.Fatal("dave 缺失字段必须跳过，不得伪造/串用他人值")
	}
	if bySubj[subjDave].Record[fieldName] != "***REDACTED***" {
		t.Fatalf("dave 其余字段应正常返回, got=%v", bySubj[subjDave].Record)
	}

	// 逐条审计与整批关联：每个主体一条，可追溯输入/依据/实际返回范围/拒降级原因
	linked := g.audit.ListByBatch(resp.BatchID)
	if len(linked) != 6 {
		t.Fatalf("整批关联的逐条审计应为 6 条, got=%d", len(linked))
	}
	seenAudit := map[int64]bool{}
	linkedSubj := map[SubjectID]AuditRecord{}
	for _, a := range linked {
		if a.BatchID != resp.BatchID {
			t.Fatalf("审计串位：audit#%d batchID=%d want=%d", a.ID, a.BatchID, resp.BatchID)
		}
		if seenAudit[a.ID] {
			t.Fatalf("逐条审计 ID 重复: %d", a.ID)
		}
		seenAudit[a.ID] = true
		linkedSubj[a.SubjectID] = a
	}
	if daveAudit := linkedSubj[subjDave]; !daveAudit.Degraded ||
		!containsNote(daveAudit.Note, "缺失") {
		t.Fatalf("dave 降级须在审计留痕: degraded=%v note=%s", daveAudit.Degraded, daveAudit.Note)
	}
	if carolAudit := linkedSubj[subjCarol]; carolAudit.Decision.Reason != ReasonConsentWithdrawn {
		t.Fatalf("carol 审计原因错误: %s", carolAudit.Decision.Reason)
	}
	for _, r := range resp.Results {
		if r.AuditID != linkedSubj[r.Subject].ID {
			t.Fatalf("主体 %s 的 AuditID 与审计记录错配", r.Subject)
		}
	}
}

func containsNote(note, sub string) bool {
	for i := 0; i+len(sub) <= len(note); i++ {
		if note[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestBatchRetryIdempotent 重试/断点重跑幂等：
// 首次放行后，即便之后同意被撤回并发布新版本、时钟推进，同键重试仍返回首次结论，
// 且不重复读取、不重复写逐条审计、不产生第二条整批记录。
func TestBatchRetryIdempotent(t *testing.T) {
	t1 := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g := newBatchFixture(t, t1)

	// 不指定版本：批次提交时固定为当时最新版本 vBatch
	req := BatchRequest{
		Entry:          "research-cohort",
		Subjects:       []SubjectID{subjAlice, subjFrank, subjBob, subjDave},
		Purpose:        purposeTreatment,
		Category:       catVitals,
		Fields:         []FieldName{fieldName, fieldPhone, fieldHeart},
		IdempotencyKey: "cohort-2026-09-28-001",
	}
	logTestInput(t, "首次批量(最新版本)=%+v", req)
	first := g.AccessBatch(req)
	logBatchResponse(t, first)
	if first.Status != BatchProcessed || first.PolicyVersion != "vBatch" {
		t.Fatalf("首次批量应按 vBatch 处理: status=%s version=%s", first.Status, first.PolicyVersion)
	}
	if first.Allowed != 2 || first.Degraded != 1 || first.Denied != 1 {
		t.Fatalf("首次汇总异常: %+v", first)
	}
	auditBefore := g.audit.Len()
	batchesBefore := g.batches.Len()

	// 批次提交后：发布 v2（alice、frank 撤回同意），并把时钟推到未来
	v2 := Policy{
		Version: "vBatch2",
		Consents: map[SubjectID]Consent{
			subjAlice: func() Consent {
				c := CloneConsent(mustConsent(g.archive, "vBatch", subjAlice))
				c.Withdrawn = true
				return c
			}(),
			subjFrank: func() Consent {
				c := CloneConsent(mustConsent(g.archive, "vBatch", subjFrank))
				c.Withdrawn = true
				return c
			}(),
			subjBob:   mustConsent(g.archive, "vBatch", subjBob),
			subjDave:  mustConsent(g.archive, "vBatch", subjDave),
			subjCarol: mustConsent(g.archive, "vBatch", subjCarol),
			subjErin:  mustConsent(g.archive, "vBatch", subjErin),
		},
		Identifiers: []FieldName{fieldName, fieldPhone},
		Masking: map[FieldName]MaskingRule{
			fieldName:  {Field: fieldName, Action: MaskRedact},
			fieldPhone: {Field: fieldPhone, Action: MaskPartial},
		},
		CreatedAt: t1.Add(24 * time.Hour),
	}
	g.archive.Put(v2)
	t2 := t1.Add(24 * time.Hour)
	g.clock = func() time.Time { return t2 }
	g.decider.clock = func() time.Time { return t2 }

	// 断点重跑：相同幂等键（含重复主体，顺序也打乱），必须原样返回首次结论
	retryReq := BatchRequest{
		Entry:          req.Entry,
		Subjects:       []SubjectID{subjBob, subjAlice, subjFrank, subjDave, subjAlice},
		Purpose:        req.Purpose,
		Category:       req.Category,
		Fields:         req.Fields,
		IdempotencyKey: req.IdempotencyKey,
	}
	logTestInput(t, "次日断点重跑(已发布撤回版本vBatch2)=%+v", retryReq)
	second := g.AccessBatch(retryReq)
	logBatchResponse(t, second)

	if !second.Cached {
		t.Fatal("同键重试必须命中幂等缓存并标记 Cached")
	}
	if second.BatchID != first.BatchID {
		t.Fatalf("重试不得产生新整批记录: first=%d second=%d", first.BatchID, second.BatchID)
	}
	if second.PolicyVersion != "vBatch" || !second.EvaluatedAt.Equal(t1) {
		t.Fatalf("重试口径必须锁定首批: version=%s at=%s", second.PolicyVersion, second.EvaluatedAt)
	}
	if !reflect.DeepEqual(second.Results, first.Results) {
		t.Fatalf("重试结论必须与首批逐字节一致:\nfirst=%+v\nsecond=%+v", first.Results, second.Results)
	}
	if got := g.audit.Len(); got != auditBefore {
		t.Fatalf("重试不得重复写逐条审计: before=%d after=%d", auditBefore, got)
	}
	if got := g.batches.Len(); got != batchesBefore {
		t.Fatalf("重试不得新增整批记录: before=%d after=%d", batchesBefore, got)
	}

	// 而新请求（无幂等键 / 新键）必须反映当前最新口径：alice、frank 已拒绝
	fresh := g.AccessBatch(BatchRequest{
		Entry: "research-cohort", Subjects: []SubjectID{subjAlice, subjFrank},
		Purpose: purposeTreatment, Category: catVitals, Fields: []FieldName{fieldHeart},
	})
	logTestInput(t, "同参数新请求(应走最新版本vBatch2)")
	logBatchResponse(t, fresh)
	if fresh.PolicyVersion != "vBatch2" || fresh.Denied != 2 {
		t.Fatalf("新请求必须反映撤回后的最新口径: version=%s denied=%d", fresh.PolicyVersion, fresh.Denied)
	}
}

// TestBatchReplayConsistent 历史回放一致性：
// 回放按当时落盘的整批不可变快照还原（含部分成功/拒绝/降级、原因与实际返回范围），
// 不受现在变化的同意状态与最新策略影响；并能与逐条审计互相关联。
func TestBatchReplayConsistent(t *testing.T) {
	t1 := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g := newBatchFixture(t, t1)

	req := BatchRequest{
		Entry: "ward-round",
		Subjects: []SubjectID{
			subjAlice, subjBob, subjCarol, subjDave, subjErin, subjFrank,
		},
		Purpose:  purposeTreatment,
		Category: catVitals,
		Fields:   []FieldName{fieldName, fieldPhone, fieldHeart},
		Version:  "vBatch",
	}
	logTestInput(t, "历史批量=%+v", req)
	original := g.AccessBatch(req)
	logBatchResponse(t, original)

	// 事后：撤回所有同意并发布新版本、推进时钟
	v2 := Policy{Version: "vBatch2", CreatedAt: t1.Add(time.Hour)}
	if p, ok := g.archive.Get("vBatch"); ok {
		v2.Identifiers = append([]FieldName(nil), p.Identifiers...)
		v2.Masking = p.Masking
		v2.Consents = make(map[SubjectID]Consent, len(p.Consents))
		for s, c := range p.Consents {
			c2 := CloneConsent(c)
			c2.Withdrawn = true
			v2.Consents[s] = c2
		}
	}
	g.archive.Put(v2)
	t2 := t1.Add(72 * time.Hour)
	g.clock = func() time.Time { return t2 }
	g.decider.clock = func() time.Time { return t2 }

	replayed, ok := g.ReplayBatch(original.BatchID)
	logTestInput(t, "72 小时后回放整批 batchID=%d（期间全部同意已撤回并发布 vBatch2）", original.BatchID)
	logBatchResponse(t, replayed)
	if !ok {
		t.Fatal("历史整批记录必须可回放")
	}
	if replayed.Cached {
		t.Fatal("回放结果不应被标记为缓存命中")
	}
	if !reflect.DeepEqual(replayed, original) {
		t.Fatalf("回放必须还原当时整批结果（含部分成功/拒绝/降级与返回范围）:\noriginal=%+v\nreplayed=%+v",
			original, replayed)
	}
	// 不存在的批次
	if _, ok := g.ReplayBatch(99999); ok {
		t.Fatal("不存在的批次回放应返回 false")
	}

	// 回放结论与逐条审计互相关联：每条审计都可通过批次 ID 找回，且版本/原因一致
	linked := g.audit.ListByBatch(original.BatchID)
	if len(linked) != original.Total {
		t.Fatalf("回放批次关联逐条审计数错误: got=%d want=%d", len(linked), original.Total)
	}
	bySubj := map[SubjectID]SubjectResult{}
	for _, r := range replayed.Results {
		bySubj[r.Subject] = r
	}
	for _, a := range linked {
		r, exists := bySubj[a.SubjectID]
		if !exists {
			t.Fatalf("审计主体 %s 在回放批次中缺失", a.SubjectID)
		}
		if a.PolicyVersion != r.Decision.PolicyVersion ||
			a.Decision.Reason != r.Decision.Reason ||
			a.Decision.Allowed != r.Decision.Allowed {
			t.Fatalf("主体 %s 回放结论与逐条审计不一致", a.SubjectID)
		}
		if r.Status == SubjectAllowed && len(a.FieldsReturned) != len(r.Record) {
			t.Fatalf("主体 %s 审计返回范围与回放记录不符", a.SubjectID)
		}
	}

	// 单主体历史回放同样按当时版本复现，且可在批次上下文中解释
	for _, a := range linked {
		redone := g.decider.DecideAt(a.SubjectID, a.Purpose, a.Category,
			a.PolicyVersion, original.EvaluatedAt, true, mustPolicy(g, a.PolicyVersion))
		if redone.Allowed != a.Decision.Allowed || redone.Reason != a.Decision.Reason {
			t.Fatalf("主体 %s 用当时版本/时刻重算结论与审计不符", a.SubjectID)
		}
	}
}

func mustPolicy(g *Gateway, version string) Policy {
	p, ok := g.archive.Get(version)
	if !ok {
		panic("policy missing: " + version)
	}
	return p
}

// mustConsent 从指定策略版本读取某主体的同意副本，供测试构造后续版本
func mustConsent(a *PolicyArchive, version string, s SubjectID) Consent {
	p, ok := a.Get(version)
	if !ok {
		panic("policy missing: " + version)
	}
	return p.Consents[s]
}

// TestBatchOverLimitAndEmpty 容量控制：超上限整批明确拒绝（不读取、不写逐条审计）；
// 空列表/仅空标识同样拒绝；限制可通过 Gateway.BatchLimit 配置。
func TestBatchOverLimitAndEmpty(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g := newBatchFixture(t, now)
	g.BatchLimit = 3

	mk := func(n int) []SubjectID {
		out := make([]SubjectID, n)
		for i := range out {
			out[i] = SubjectID("s" + strconv.Itoa(i))
		}
		return out
	}

	// 超限：明确拒绝结果（首次就带幂等键，验证被拒批次重试也幂等）
	over := BatchRequest{
		Entry: "ward-round", Subjects: mk(4), Purpose: purposeTreatment,
		Category: catVitals, Fields: []FieldName{fieldHeart}, Version: "vBatch",
		IdempotencyKey: "over-limit-key",
	}
	logTestInput(t, "超限批量 subjects=%v（上限3）", over.Subjects)
	resp := g.AccessBatch(over)
	logBatchResponse(t, resp)
	if resp.Status != BatchRejected || resp.Reason != ReasonBatchTooLarge {
		t.Fatalf("超限必须整批拒绝: status=%s reason=%s", resp.Status, resp.Reason)
	}
	if resp.Results != nil {
		t.Fatal("超限整批拒绝不得返回任何主体结果")
	}
	if g.audit.Len() != 0 {
		t.Fatalf("整批在处理前拒绝，不得产生逐条审计, got=%d", g.audit.Len())
	}
	if g.batches.Len() != 1 {
		t.Fatalf("整批拒绝仍要落整批审计记录, got=%d", g.batches.Len())
	}

	// 同键重试一个被超限拒绝的批次：同样幂等，不重复落记录
	retry := g.AccessBatch(over)
	if !retry.Cached || retry.BatchID != resp.BatchID || retry.Reason != ReasonBatchTooLarge {
		t.Fatalf("超限拒绝的同键重试必须幂等返回原拒绝: cached=%v id %d->%d",
			retry.Cached, resp.BatchID, retry.BatchID)
	}
	if g.batches.Len() != 1 {
		t.Fatalf("超限拒绝重试不得重复落整批记录, got=%d", g.batches.Len())
	}

	// 恰好等于上限：正常处理（这些主体无同意，会各自得到 consent_missing，不拖垮整批）
	eq := BatchRequest{
		Entry: "ward-round", Subjects: []SubjectID{subjAlice, subjBob, subjFrank},
		Purpose: purposeTreatment, Category: catVitals,
		Fields: []FieldName{fieldHeart}, Version: "vBatch",
	}
	respEq := g.AccessBatch(eq)
	logTestInput(t, "恰好达上限(3) subjects=%v", eq.Subjects)
	logBatchResponse(t, respEq)
	if respEq.Status != BatchProcessed || respEq.Total != 3 {
		t.Fatalf("达上限应正常处理: status=%s total=%d", respEq.Status, respEq.Total)
	}

	// 空列表
	empty := g.AccessBatch(BatchRequest{Entry: "x", Purpose: purposeTreatment, Category: catVitals, Version: "vBatch"})
	if empty.Status != BatchRejected || empty.Reason != ReasonBatchEmpty {
		t.Fatalf("空批次必须拒绝: %+v", empty)
	}
	// 仅空标识：去重后为空
	onlyBlank := g.AccessBatch(BatchRequest{
		Entry: "x", Subjects: []SubjectID{"", ""}, Purpose: purposeTreatment, Category: catVitals,
	})
	if onlyBlank.Status != BatchRejected || onlyBlank.Reason != ReasonBatchEmpty {
		t.Fatalf("仅空标识批次必须按空批拒绝: %+v", onlyBlank)
	}
	t.Logf("【判定】空/超限批次均明确拒绝，整批记录数=%d 逐条审计数=%d", g.batches.Len(), g.audit.Len())
}

// TestBatchConcurrentAudit 并发与大批量：多个批次并发提交，
// 结果、逐条审计、整批记录都不丢失、不覆盖、不串位（配合 -race）。
func TestBatchConcurrentAudit(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g := newBatchFixture(t, now)

	const batchesN = 40
	const perBatch = 6 // alice bob carol dave erin frank
	var wg sync.WaitGroup
	wg.Add(batchesN)
	responses := make([]BatchResponse, batchesN)
	t0 := time.Now()
	for b := 0; b < batchesN; b++ {
		b := b
		go func() {
			defer wg.Done()
			// 每个批次顺序略作轮换，验证高并发下顺序仍稳定
			subs := []SubjectID{subjAlice, subjBob, subjCarol, subjDave, subjErin, subjFrank}
			if b%2 == 1 {
				subs = []SubjectID{subjFrank, subjErin, subjDave, subjCarol, subjBob, subjAlice}
			}
			responses[b] = g.AccessBatch(BatchRequest{
				Entry:    "ward-" + strconv.Itoa(b),
				Subjects: subs,
				Purpose:  purposeTreatment,
				Category: catVitals,
				Fields:   []FieldName{fieldName, fieldPhone, fieldHeart},
				Version:  "vBatch",
			})
		}()
	}
	wg.Wait()
	logTestInput(t, "%d 个批次 × %d 主体并发，耗时 %v", batchesN, perBatch, time.Since(t0))

	// 整批记录完整、BatchID 唯一
	if g.batches.Len() != batchesN {
		t.Fatalf("整批记录丢失: want=%d got=%d", batchesN, g.batches.Len())
	}
	batchIDs := map[int64]bool{}
	for i, resp := range responses {
		if resp.Status != BatchProcessed || resp.Total != perBatch {
			t.Fatalf("批次 %d 结果不完整: %+v", i, resp)
		}
		if batchIDs[resp.BatchID] {
			t.Fatalf("BatchID 重复（覆盖）: %d", resp.BatchID)
		}
		batchIDs[resp.BatchID] = true
		if resp.Allowed != 2 || resp.Degraded != 1 || resp.Denied != 3 {
			t.Fatalf("批次 %d 汇总错误: %+v", i, resp)
		}
		// 每批顺序与请求一致
		want := []SubjectID{subjAlice, subjBob, subjCarol, subjDave, subjErin, subjFrank}
		if i%2 == 1 {
			want = []SubjectID{subjFrank, subjErin, subjDave, subjCarol, subjBob, subjAlice}
		}
		for j, s := range want {
			if resp.Results[j].Subject != s {
				t.Fatalf("批次 %d 主体串位/乱序 at %d: got=%s want=%s", i, j, resp.Results[j].Subject, s)
			}
			if resp.Results[j].AuditID == 0 {
				t.Fatalf("批次 %d 主体 %s 缺少逐条审计 ID", i, s)
			}
		}
	}

	// 逐条审计：总数 = 批次数×每批人数，全部正确关联批次，无错配
	if g.audit.Len() != batchesN*perBatch {
		t.Fatalf("逐条审计丢失: want=%d got=%d", batchesN*perBatch, g.audit.Len())
	}
	perBatchCount := map[int64]int{}
	auditIDSeen := map[int64]bool{}
	for _, a := range g.audit.List() {
		if a.BatchID <= 0 || !batchIDs[a.BatchID] {
			t.Fatalf("审计记录批次关联错误: audit#%d batchID=%d", a.ID, a.BatchID)
		}
		if auditIDSeen[a.ID] {
			t.Fatalf("逐条审计 ID 重复（覆盖）: %d", a.ID)
		}
		auditIDSeen[a.ID] = true
		perBatchCount[a.BatchID]++
	}
	for id, c := range perBatchCount {
		if c != perBatch {
			t.Fatalf("整批 %d 关联审计数错误: %d", id, c)
		}
	}
	t.Logf("【判定】整批记录=%d 逐条审计=%d 全部唯一且关联正确", g.batches.Len(), g.audit.Len())
}

// TestBatchConcurrentSameKey 同一幂等键并发提交：只有一个批次真正执行，
// 所有调用方拿到完全相同的结论与 BatchID，审计只写一份。
func TestBatchConcurrentSameKey(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g := newBatchFixture(t, now)

	const n = 30
	var wg sync.WaitGroup
	wg.Add(n)
	resps := make([]BatchResponse, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			resps[i] = g.AccessBatch(BatchRequest{
				Entry: "cohort", Subjects: []SubjectID{subjAlice, subjBob, subjDave, subjFrank},
				Purpose: purposeTreatment, Category: catVitals,
				Fields: []FieldName{fieldName, fieldPhone, fieldHeart}, Version: "vBatch",
				IdempotencyKey: "same-key-001",
			})
		}()
	}
	close(start)
	wg.Wait()
	logTestInput(t, "%d 个并发同键请求 key=same-key-001", n)

	first := resps[0]
	executed, cached := 0, 0
	for _, r := range resps {
		if r.BatchID != first.BatchID || !reflect.DeepEqual(r.Results, first.Results) {
			t.Fatalf("同键并发结论不一致: first=%d other=%d", first.BatchID, r.BatchID)
		}
		if r.Cached {
			cached++
		} else {
			executed++
		}
	}
	if executed != 1 || cached != n-1 {
		t.Fatalf("同键应恰好执行一次: executed=%d cached=%d", executed, cached)
	}
	if g.batches.Len() != 1 {
		t.Fatalf("同键只能产生一条整批记录, got=%d", g.batches.Len())
	}
	if g.audit.Len() != 4 {
		t.Fatalf("同键只能产生一份逐条审计(4条), got=%d", g.audit.Len())
	}
	t.Logf("【判定】执行=%d 缓存=%d 整批记录=%d 逐条审计=%d，结论与BatchID完全一致",
		executed, cached, g.batches.Len(), g.audit.Len())
}

// TestBatchCompatibleWithSingleAccess 批量层与单主体访问共用同一流水线：
// 同一主体在批量内与单主体访问的判定、最小化、脱敏结果一致；
// 单主体审计 BatchID=0，不与批量记录互相污染。
func TestBatchCompatibleWithSingleAccess(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g := newBatchFixture(t, now)

	fields := []FieldName{fieldName, fieldPhone, fieldHeart}

	// 单主体访问 alice
	single := g.Access(AccessRequest{
		Entry: "clinical-ui", Subject: subjAlice, Purpose: purposeTreatment,
		Category: catVitals, Fields: fields, Version: "vBatch",
	})
	logTestInput(t, "单主体访问 alice fields=%v version=vBatch", fields)
	t.Logf("【单主体】auditID=%d record=%v degraded=%v", single.AuditID, single.Record, single.Degraded)

	// 批量内包含 alice
	batch := g.AccessBatch(BatchRequest{
		Entry: "ward-round", Subjects: []SubjectID{subjAlice, subjFrank},
		Purpose: purposeTreatment, Category: catVitals, Fields: fields, Version: "vBatch",
	})
	logBatchResponse(t, batch)

	var inBatch SubjectResult
	for _, r := range batch.Results {
		if r.Subject == subjAlice {
			inBatch = r
		}
	}
	if single.Decision.Allowed != inBatch.Decision.Allowed ||
		single.Decision.Reason != inBatch.Decision.Reason {
		t.Fatal("单主体与批量内同主体的判定必须一致")
	}
	if !reflect.DeepEqual(single.Record, inBatch.Record) {
		t.Fatalf("单主体与批量内脱敏结果必须一致: single=%v batch=%v", single.Record, inBatch.Record)
	}

	// 审计互不污染：单主体记录 BatchID=0；批量逐条记录均带 BatchID
	singleAudit, _ := g.audit.Get(single.AuditID)
	if singleAudit.BatchID != 0 {
		t.Fatalf("单主体审计不得关联批次, BatchID=%d", singleAudit.BatchID)
	}
	if len(g.audit.ListByBatch(0)) != 0 {
		t.Fatal("ListByBatch(0) 不应返回单主体审计，避免批量/单主体审计串台")
	}
	linked := g.audit.ListByBatch(batch.BatchID)
	if len(linked) != 2 {
		t.Fatalf("批量逐条审计应为 2 条, got=%d", len(linked))
	}
	for _, a := range linked {
		if a.BatchID != batch.BatchID {
			t.Fatal("批量逐条审计必须全部关联到本批")
		}
	}
	// 单主体回放仍按原方式工作
	redone, ok := g.Replay(single.AuditID)
	if !ok || !redone.Allowed || redone.PolicyVersion != "vBatch" {
		t.Fatalf("既有单主体回放不得回归: %+v ok=%v", redone, ok)
	}
}
