package gateway

import (
	"strings"
	"testing"
	"time"
)

func newFixture(t *testing.T, now time.Time) (*Gateway, *AuditLog) {
	t.Helper()
	archive, _, _ := buildPolicies(now)
	store := seedStore()
	audit := NewAuditLog()
	g := New(archive, store, audit)
	g.clock = func() time.Time { return now }
	d := g.decider
	d.clock = func() time.Time { return now }
	return g, audit
}

func TestAccessAllowedMinimizedAndMasked(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	g, audit := newFixture(t, now)

	req := AccessRequest{
		Entry:    "clinical-ui",
		Subject:  subjAlice,
		Purpose:  purposeTreatment,
		Category: catVitals,
		Fields:   []FieldName{fieldName, fieldPhone, fieldHeart},
		Version:  "v1",
	}
	logTestInput(t, "请求=%+v", req)
	resp := g.Access(req)
	logDecision(t, resp.Decision)
	t.Logf("【输出】auditID=%d record=%v", resp.AuditID, resp.Record)
	dumpAudit(t, audit)

	if !resp.Decision.Allowed {
		t.Fatalf("应放行: %s", resp.Decision.Basis)
	}
	if resp.Record[fieldName] != "***REDACTED***" {
		t.Fatalf("姓名应整值抹除, got=%q", resp.Record[fieldName])
	}
	if resp.Record[fieldPhone] == "13812345678" || !strings.Contains(resp.Record[fieldPhone], "****") {
		t.Fatalf("手机号应局部脱敏, got=%q", resp.Record[fieldPhone])
	}
	if resp.Record[fieldHeart] != "72" {
		t.Fatalf("非标识字段应原样返回, got=%q", resp.Record[fieldHeart])
	}
	if _, leaked := resp.Record["diagnosis"]; leaked {
		t.Fatal("结果不得包含未请求字段")
	}
}

func TestAccessDeniedWritesAudit(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	g, audit := newFixture(t, now)

	req := AccessRequest{
		Entry: "research-api", Subject: subjAlice, Purpose: purposeResearch,
		Category: catVitals, Fields: []FieldName{fieldHeart}, Version: "v1",
	}
	logTestInput(t, "请求=%+v (用途越界)", req)
	resp := g.Access(req)
	logDecision(t, resp.Decision)
	if resp.Record != nil {
		t.Fatal("拒绝时不得返回数据")
	}
	assertReason(t, resp.Decision, ReasonPurposeOutOfScope)
	if audit.Len() != 1 {
		t.Fatalf("拒绝也必须写审计, got=%d", audit.Len())
	}
	rec, _ := audit.Get(resp.AuditID)
	if rec.PolicyVersion != "v1" {
		t.Fatalf("审计必须标注策略版本, got=%s", rec.PolicyVersion)
	}
}

func TestFieldMissingFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	archive, v1, _ := buildPolicies(now)
	// v1 白名单增加一个记录里不存在的字段
	alice := CloneConsent(v1.Consents[subjAlice])
	alice.Fields = append(alice.Fields, fieldDiag)
	pol := Policy{
		Version: "vMissing", Consents: map[SubjectID]Consent{subjAlice: alice},
		Identifiers: v1.Identifiers, Masking: v1.Masking, CreatedAt: now,
	}
	archive.Put(pol)

	audit := NewAuditLog()
	g := New(archive, seedStore(), audit)
	g.clock = func() time.Time { return now }
	g.decider.clock = func() time.Time { return now }

	req := AccessRequest{
		Entry: "clinical-ui", Subject: subjAlice, Purpose: purposeTreatment,
		Category: catVitals, Fields: []FieldName{fieldHeart, fieldDiag}, Version: "vMissing",
	}
	logTestInput(t, "请求=%+v (白名单字段 diagnosis 在记录中缺失)", req)
	resp := g.Access(req)
	logDecision(t, resp.Decision)
	dumpAudit(t, audit)

	if resp.Decision.Allowed || resp.Record != nil {
		t.Fatal("字段缺失时必须 fail-closed 拒绝，不得静默返回部分原始数据")
	}
	assertReason(t, resp.Decision, ReasonMinimizationFailed)
}

func TestDegradeSkipsProblemField(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	archive, v1, _ := buildPolicies(now)
	// 新策略把 heart_rate 错误标成标识字段但不提供脱敏规则 -> 策略无法匹配
	pol := Policy{
		Version: "vBadRule",
		Consents: map[SubjectID]Consent{
			subjAlice: CloneConsent(v1.Consents[subjAlice]),
		},
		Identifiers: append(append([]FieldName(nil), v1.Identifiers...), fieldHeart),
		Masking:     v1.Masking, // heart_rate 无规则
		CreatedAt:   now,
	}
	archive.Put(pol)

	audit := NewAuditLog()
	g := New(archive, seedStore(), audit)
	g.Degrade = DegradeSkip
	g.clock = func() time.Time { return now }
	g.decider.clock = func() time.Time { return now }

	req := AccessRequest{
		Entry: "clinical-ui", Subject: subjAlice, Purpose: purposeTreatment,
		Category: catVitals, Fields: []FieldName{fieldName, fieldPhone, fieldHeart}, Version: "vBadRule",
	}
	logTestInput(t, "请求=%+v (heart_rate 是标识字段但无脱敏策略，降级模式)", req)
	resp := g.Access(req)
	logDecision(t, resp.Decision)
	t.Logf("【输出】record=%v", resp.Record)
	dumpAudit(t, audit)

	if !resp.Decision.Allowed {
		t.Fatal("降级模式下应放行其余字段")
	}
	if _, ok := resp.Record[fieldHeart]; ok {
		t.Fatal("无匹配策略的标识字段必须跳过，不得返回原文")
	}
	if resp.Record[fieldName] != "***REDACTED***" {
		t.Fatal("其余字段仍应正常脱敏返回")
	}
	rec, _ := audit.Get(resp.AuditID)
	if !strings.Contains(rec.Note, "无匹配脱敏策略") {
		t.Fatalf("降级跳过必须在审计留痕, note=%s", rec.Note)
	}
}

func TestPolicyVersionReplay(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	g, audit := newFixture(t, now)

	// v1 时同意有效
	reqV1 := AccessRequest{
		Entry: "clinical-ui", Subject: subjAlice, Purpose: purposeTreatment,
		Category: catVitals, Fields: []FieldName{fieldHeart}, Version: "v1",
	}
	logTestInput(t, "历史请求(v1)=%+v", reqV1)
	respV1 := g.Access(reqV1)
	logDecision(t, respV1.Decision)
	if !respV1.Decision.Allowed {
		t.Fatal("v1 时应放行")
	}

	// 当前最新版本为 v2（已撤回），直接访问应拒绝
	respLatest := g.Access(AccessRequest{
		Entry: "clinical-ui", Subject: subjAlice, Purpose: purposeTreatment,
		Category: catVitals, Fields: []FieldName{fieldHeart},
	})
	logTestInput(t, "同请求但走最新版本(v2)")
	logDecision(t, respLatest.Decision)
	if respLatest.Decision.Allowed {
		t.Fatal("v2 撤回后最新版本必须拒绝")
	}

	// 回放历史审计：必须按当时标注的 v1 复现出“放行”
	replayed, ok := g.Replay(respV1.AuditID)
	t.Logf("【回放审计#%d】按记录标注版本 %s 重新判定", respV1.AuditID, respV1.Decision.PolicyVersion)
	logDecision(t, replayed)
	if !ok {
		t.Fatal("审计记录应存在")
	}
	if !replayed.Allowed || replayed.Reason != respV1.Decision.Reason {
		t.Fatalf("历史结论不可复现: replayed=%+v original=%+v", replayed, respV1.Decision)
	}
	if replayed.PolicyVersion != "v1" {
		t.Fatalf("回放必须使用历史版本 v1, got=%s", replayed.PolicyVersion)
	}
	_ = audit
}
