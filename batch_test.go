package gateway

import (
	"strings"
	"testing"
	"time"
)

// TestBatchMixedSubjectsIndependent：混合批次，每人独立判定，拒绝不拖垮整批，顺序稳定
func TestBatchMixedSubjectsIndependent(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g, _, audit := newBatchFixture(t, now)

	req := BatchRequest{
		Entry:    "ward-round",
		Purpose:  purposeTreatment,
		Category: catVitals,
		Fields:   []FieldName{fieldName, fieldPhone, fieldHeart},
		Version:  "vBatch",
		Subjects: []SubjectID{subjAlice, subjCarol, subjDave, subjErin},
	}
	logBatchInput(t, req, "vBatch")
	resp := g.BatchAccess(req)
	logBatchResult(t, resp)
	dumpBatchAudit(t, audit, resp.BatchID)

	if resp.Rejected {
		t.Fatalf("批次不应被整体拒绝: %s", resp.Message)
	}
	if len(resp.Outcomes) != 4 {
		t.Fatalf("结果数应为 4, got=%d", len(resp.Outcomes))
	}
	// 稳定顺序与主体绑定
	want := []struct {
		s      SubjectID
		st     OutcomeStatus
		reason DenyReason
	}{
		{subjAlice, StatusAllowed, ReasonAllowed},
		{subjCarol, StatusDenied, ReasonPurposeOutOfScope},
		{subjDave, StatusDenied, ReasonConsentExpired},
		{subjErin, StatusDenied, ReasonRecordNotFound},
	}
	for i, w := range want {
		o := resp.Outcomes[i]
		if o.Index != i || o.Subject != w.s {
			t.Fatalf("位置 %d 顺序错配: got=%s want=%s", i, o.Subject, w.s)
		}
		if o.Status != w.st || o.Decision.Reason != w.reason {
			t.Fatalf("主体 %s 结论错误: status=%s reason=%q want=%s/%q",
				w.s, o.Status, o.Decision.Reason, w.st, w.reason)
		}
	}
	// 汇总
	if resp.Summary != (BatchSummary{Total: 4, Allowed: 1, Denied: 3}) {
		t.Fatalf("汇总错误: %+v", resp.Summary)
	}
	// 放行者数据正常脱敏，拒绝者无数据，互不串数据
	if resp.Outcomes[0].Record[fieldName] != "***REDACTED***" {
		t.Fatal("alice 姓名应整值抹除")
	}
	if !strings.Contains(resp.Outcomes[0].Record[fieldPhone], "****") {
		t.Fatal("alice 手机号应局部脱敏")
	}
	for i := 1; i < 4; i++ {
		if resp.Outcomes[i].Record != nil {
			t.Fatalf("主体 %s 被拒绝时不得返回数据", resp.Outcomes[i].Subject)
		}
	}
	// 每人独立审计 + 一条批次汇总
	if got := len(audit.ListByBatch(resp.BatchID)); got != 5 {
		t.Fatalf("批次审计应为 1 汇总 + 4 主体 = 5 条, got=%d", got)
	}
}

// TestBatchPinnedVersionAndTime：整批固定同一时刻与版本；提交后的撤回不改变本批结论
func TestBatchPinnedVersionAndTime(t *testing.T) {
	submittedAt := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g, archive, audit := newBatchFixture(t, submittedAt)

	// 不指定版本：整批固定为提交时刻的最新版本 vBatch
	req := BatchRequest{
		Entry: "cohort-research", Purpose: purposeTreatment, Category: catVitals,
		Fields:   []FieldName{fieldHeart},
		Subjects: []SubjectID{subjAlice},
	}
	logBatchInput(t, req, "(提交时刻最新=vBatch)")
	resp := g.BatchAccess(req)
	logBatchResult(t, resp)

	if resp.PolicyVersion != "vBatch" {
		t.Fatalf("整批应固定在 vBatch, got=%s", resp.PolicyVersion)
	}
	if !resp.EvaluatedAt.Equal(submittedAt) {
		t.Fatalf("判断时刻应固定为提交时刻, got=%s", resp.EvaluatedAt)
	}
	if !resp.Outcomes[0].Decision.Allowed {
		t.Fatal("vBatch 下 alice 应放行")
	}
	firstAuditCount := audit.Len()

	// 提交之后撤回才生效（发布 vBatchAfter）：新请求应拒绝，但已确定的批次结论不变
	laterAt := submittedAt.Add(2 * time.Hour)
	publishWithdrawnVersion(archive, mustPolicy(t, archive, "vBatch"), laterAt)
	g.clock = func() time.Time { return laterAt }
	g.decider.clock = func() time.Time { return laterAt }

	newResp := g.BatchAccess(BatchRequest{
		Entry: "cohort-research", Purpose: purposeTreatment, Category: catVitals,
		Fields: []FieldName{fieldHeart}, Subjects: []SubjectID{subjAlice},
	})
	logBatchResult(t, newResp)
	if newResp.PolicyVersion != "vBatchAfter" || newResp.Outcomes[0].Decision.Allowed {
		t.Fatal("提交后的新请求必须反映撤回（vBatchAfter 拒绝）")
	}

	// 历史批次回放仍还原 vBatch 放行，不受现在撤回影响
	replayed, ok := g.ReplayBatch(resp.BatchID)
	t.Logf("【批次回放】batchID=%s allMatch=%v", resp.BatchID, replayed.AllMatch)
	if !ok || !replayed.Found {
		t.Fatal("历史批次应可回放")
	}
	if replayed.PolicyVersion != "vBatch" || len(replayed.Subjects) != 1 {
		t.Fatalf("回放口径错误: ver=%s n=%d", replayed.PolicyVersion, len(replayed.Subjects))
	}
	sr := replayed.Subjects[0]
	if sr.Status != StatusAllowed || !sr.Recorded.Allowed || !sr.RecheckMatches {
		t.Fatalf("历史放行结论必须可复现: %+v", sr)
	}
	if !replayed.EvaluatedAt.Equal(submittedAt) {
		t.Fatalf("回放判断时刻应为提交时刻: %s", replayed.EvaluatedAt)
	}
	// 回放不得新增审计记录
	if audit.Len() != firstAuditCount+2 { // 新批次：1 主体 + 1 汇总
		t.Fatalf("回放不应额外写审计: before=%d after=%d", firstAuditCount, audit.Len())
	}
}

func mustPolicy(t *testing.T, archive *PolicyArchive, version string) Policy {
	t.Helper()
	p, ok := archive.Get(version)
	if !ok {
		t.Fatalf("策略 %s 应存在", version)
	}
	return p
}

// TestBatchIdempotentRetry：相同幂等键重试不重复处理、不重复读取、不重复审计，结论逐字节一致
func TestBatchIdempotentRetry(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g, _, audit := newBatchFixture(t, now)

	req := BatchRequest{
		Entry: "ward-round", IdempotencyKey: "job-20260928-001",
		Purpose: purposeTreatment, Category: catVitals,
		Fields:   []FieldName{fieldName, fieldPhone, fieldHeart},
		Subjects: []SubjectID{subjAlice, subjCarol, subjErin},
	}
	logBatchInput(t, req, "vBatch")
	first := g.BatchAccess(req)
	logBatchResult(t, first)
	auditAfterFirst := audit.Len()

	// 第一次：3 主体 + 1 汇总 = 4 条
	if auditAfterFirst != 4 {
		t.Fatalf("首次批次应有 4 条审计, got=%d", auditAfterFirst)
	}

	// 重试（断点重跑）：必须原样返回，且不新增任何审计
	for attempt := 2; attempt <= 3; attempt++ {
		retried := g.BatchAccess(req)
		if retried.BatchID != first.BatchID {
			t.Fatalf("第 %d 次重试必须返回同一批次 ID: %s vs %s", attempt, retried.BatchID, first.BatchID)
		}
		if retried.Summary != first.Summary {
			t.Fatalf("第 %d 次重试汇总不一致", attempt)
		}
		for i := range first.Outcomes {
			a, b := first.Outcomes[i], retried.Outcomes[i]
			if a.AuditID != b.AuditID || a.Status != b.Status || a.Decision.Reason != b.Decision.Reason {
				t.Fatalf("第 %d 次重试主体 %d 结论不一致", attempt, i)
			}
		}
		if audit.Len() != auditAfterFirst {
			t.Fatalf("第 %d 次重试不得新增审计: %d vs %d", attempt, audit.Len(), auditAfterFirst)
		}
		t.Logf("【重试 %d】batchID=%s 与首次一致，审计条数仍=%d（无重复读取/重复审计）",
			attempt, retried.BatchID, audit.Len())
	}

	// 即使之后同意撤回，带幂等键的重跑仍返回首次结论（已确定结论不被改写）
	rejected := g.BatchAccess(req)
	if rejected.BatchID != first.BatchID || rejected.Outcomes[0].Status != StatusAllowed {
		t.Fatal("已完成批次的重跑必须返回首次结论，不受后续状态变化影响")
	}
}

// TestBatchOverLimitRejected：超过批量上限时清楚拒绝，且不处理任何主体
func TestBatchOverLimitRejected(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g, _, audit := newBatchFixture(t, now)

	subjects := make([]SubjectID, MaxBatchSubjects+1)
	for i := range subjects {
		subjects[i] = SubjectID("s" + itoa(i))
	}
	req := BatchRequest{
		Entry: "bulk-export", IdempotencyKey: "too-big",
		Purpose: purposeTreatment, Category: catVitals,
		Fields: []FieldName{fieldHeart}, Subjects: subjects,
	}
	logBatchInput(t, req, "vBatch")
	resp := g.BatchAccess(req)
	logBatchResult(t, resp)

	if !resp.Rejected || resp.Reason != ReasonBatchTooLarge {
		t.Fatalf("超限批次必须整体拒绝: rejected=%v reason=%q", resp.Rejected, resp.Reason)
	}
	if resp.Outcomes != nil {
		t.Fatal("超限批次不得返回任何主体结果")
	}
	recs := audit.ListByBatch(resp.BatchID)
	if len(recs) != 1 || !recs[0].IsBatchHead {
		t.Fatalf("超限拒绝只应留一条批次汇总审计, got=%d", len(recs))
	}
	// 超限拒绝同样幂等
	again := g.BatchAccess(req)
	if again.BatchID != resp.BatchID || audit.Len() != 1 {
		t.Fatal("超限拒绝重试必须幂等且不重复审计")
	}
}

// TestBatchEmptyAndDuplicateRejected：空批次与批内重复主体被清楚拒绝
func TestBatchEmptyAndDuplicateRejected(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g, _, audit := newBatchFixture(t, now)

	empty := g.BatchAccess(BatchRequest{Purpose: purposeTreatment, Category: catVitals})
	t.Logf("【空批次】rejected=%v reason=%q msg=%s", empty.Rejected, empty.Reason, empty.Message)
	if !empty.Rejected || empty.Reason != ReasonBatchEmpty {
		t.Fatal("空批次必须以 batch_empty 拒绝")
	}

	dup := g.BatchAccess(BatchRequest{
		Purpose: purposeTreatment, Category: catVitals,
		Subjects: []SubjectID{subjAlice, subjAlice},
	})
	t.Logf("【重复主体】rejected=%v reason=%q msg=%s", dup.Rejected, dup.Reason, dup.Message)
	if !dup.Rejected || dup.Reason != ReasonBatchDuplicateSubject {
		t.Fatal("重复主体批次必须以 batch_duplicate_subject 拒绝")
	}
	if audit.Len() != 2 {
		t.Fatalf("两次整体拒绝各留一条汇总审计, got=%d", audit.Len())
	}
}

// TestBatchDegradePerSubject：批内某人字段缺失走降级，其他人不受影响，状态标 degraded
func TestBatchDegradePerSubject(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g, _, audit := newBatchFixture(t, now)
	g.Degrade = DegradeSkip

	// erin 的白名单含 fieldDiag，但本地记录里没有该字段 -> 仅 erin 降级
	g.store.Put(subjErin, catVitals, Record{
		fieldName: "Erin Zhou", fieldPhone: "13566667777", fieldHeart: "65",
	})
	pol := mustPolicy(t, g.archive, "vBatch")
	erinConsent := CloneConsent(pol.Consents[subjErin])
	erinConsent.Fields = append(erinConsent.Fields, fieldDiag)
	pol.Consents[subjErin] = erinConsent
	pol.Version = "vBatchDegrade"
	g.archive.Put(pol)

	req := BatchRequest{
		Entry: "ward-round", Purpose: purposeTreatment, Category: catVitals,
		Version:  "vBatchDegrade",
		Fields:   []FieldName{fieldName, fieldPhone, fieldHeart, fieldDiag},
		Subjects: []SubjectID{subjAlice, subjErin},
	}
	logBatchInput(t, req, "vBatchDegrade(erin 缺 diagnosis，降级模式)")
	resp := g.BatchAccess(req)
	logBatchResult(t, resp)
	dumpBatchAudit(t, audit, resp.BatchID)

	if resp.Summary != (BatchSummary{Total: 2, Allowed: 1, Degraded: 1}) {
		t.Fatalf("汇总应为 1 放行 1 降级: %+v", resp.Summary)
	}
	if resp.Outcomes[0].Status != StatusAllowed {
		t.Fatal("alice 应完整放行")
	}
	erin := resp.Outcomes[1]
	if erin.Status != StatusDegraded {
		t.Fatalf("erin 应标记降级, got=%s", erin.Status)
	}
	if _, leaked := erin.Record[fieldDiag]; leaked {
		t.Fatal("缺失字段不得返回")
	}
	if erin.Record[fieldName] != "***REDACTED***" {
		t.Fatal("降级者其余字段仍应正常脱敏返回")
	}
	rec, _ := audit.Get(erin.AuditID)
	if rec.Outcome != StatusDegraded || !strings.Contains(rec.Note, "降级跳过") {
		t.Fatalf("降级必须在该主体审计留痕: outcome=%s note=%s", rec.Outcome, rec.Note)
	}
}

// TestBatchReplayMixedRestoresAll：混合批次历史回放还原全部状态/返回范围/原因，且不被现状影响
func TestBatchReplayMixedRestoresAll(t *testing.T) {
	submittedAt := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g, archive, _ := newBatchFixture(t, submittedAt)

	req := BatchRequest{
		Entry: "ward-round", Purpose: purposeTreatment, Category: catVitals,
		Version: "vBatch", Fields: []FieldName{fieldName, fieldPhone, fieldHeart},
		Subjects: []SubjectID{subjAlice, subjCarol, subjDave, subjErin},
	}
	resp := g.BatchAccess(req)
	logBatchInput(t, req, "vBatch")
	logBatchResult(t, resp)

	// 提交后发布撤回版本、删除本地数据、推进时钟，模拟“现在已变天”
	publishWithdrawnVersion(archive, mustPolicy(t, archive, "vBatch"), submittedAt.Add(time.Hour))
	g.store.Put(subjAlice, catVitals, Record{}) // 清空 alice 数据
	g.clock = func() time.Time { return submittedAt.Add(30 * 24 * time.Hour) }
	g.decider.clock = func() time.Time { return submittedAt.Add(30 * 24 * time.Hour) }

	replayed, ok := g.ReplayBatch(resp.BatchID)
	if !ok {
		t.Fatal("历史批次应能回放")
	}
	t.Logf("【批次回放】batchID=%s ver=%s 时刻=%s allMatch=%v 主体数=%d",
		replayed.BatchID, replayed.PolicyVersion, replayed.EvaluatedAt.Format(time.RFC3339),
		replayed.AllMatch, len(replayed.Subjects))
	if !replayed.AllMatch {
		t.Fatal("同意层重算应与历史记录一致（固定版本+固定时刻）")
	}
	if len(replayed.Subjects) != 4 {
		t.Fatalf("回放应还原 4 个主体, got=%d", len(replayed.Subjects))
	}
	wantStatus := []OutcomeStatus{StatusAllowed, StatusDenied, StatusDenied, StatusDenied}
	wantReason := []DenyReason{
		ReasonAllowed, ReasonPurposeOutOfScope, ReasonConsentExpired, ReasonRecordNotFound,
	}
	for i, sr := range replayed.Subjects {
		t.Logf("  回放[%d] 主体=%s 状态=%s reason=%q 返回=%v match=%v",
			sr.Index, sr.Subject, sr.Status, sr.Recorded.Reason, sr.FieldsReturned, sr.RecheckMatches)
		if sr.Index != i || sr.Subject != req.Subjects[i] {
			t.Fatalf("回放位置 %d 错配", i)
		}
		if sr.Status != wantStatus[i] || sr.Recorded.Reason != wantReason[i] {
			t.Fatalf("回放主体 %s 结论被现状污染: got=%s/%q want=%s/%q",
				sr.Subject, sr.Status, sr.Recorded.Reason, wantStatus[i], wantReason[i])
		}
	}
	// 放行者历史返回范围仍可还原（3 个字段），尽管本地数据已被清空
	if len(replayed.Subjects[0].FieldsReturned) != 3 {
		t.Fatal("历史返回字段范围必须从审计记录还原")
	}

	// 不存在的批次
	if _, found := g.ReplayBatch("batch-not-exist"); found {
		t.Fatal("不存在批次回放应返回 false")
	}
}
