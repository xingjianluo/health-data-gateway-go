package gateway

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestLargeBatchNoLossNoMismatch：达到上限的大批量在本地大并发下，
// 结果不丢、审计不丢、下标不错配，且每个主体只拿到自己的数据
func TestLargeBatchNoLossNoMismatch(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)

	archive := NewPolicyArchive()
	store := NewHealthStore()
	const n = MaxBatchSubjects
	consents := make(map[SubjectID]Consent, n)
	for i := 0; i < n; i++ {
		s := SubjectID(fmt.Sprintf("subj-%03d", i))
		consents[s] = Consent{
			SubjectID:  s,
			Purposes:   []Purpose{purposeTreatment},
			Categories: []Category{catVitals},
			Fields:     []FieldName{fieldHeart, fieldPhone},
			GrantedAt:  now.AddDate(-1, 0, 0),
		}
		store.Put(s, catVitals, Record{
			fieldHeart: "7" + fmt.Sprintf("%02d", i),
			fieldPhone: "139" + fmt.Sprintf("%08d", i),
		})
	}
	archive.Put(Policy{
		Version: "vLarge", Consents: consents,
		Identifiers: []FieldName{fieldPhone},
		Masking:     map[FieldName]MaskingRule{fieldPhone: {Field: fieldPhone, Action: MaskPartial}},
		CreatedAt:   now,
	})
	audit := NewAuditLog()
	g := New(archive, store, audit)
	g.clock = func() time.Time { return now }
	g.decider.clock = func() time.Time { return now }

	subjects := make([]SubjectID, n)
	for i := range subjects {
		subjects[i] = SubjectID(fmt.Sprintf("subj-%03d", i))
	}
	req := BatchRequest{
		Entry: "bulk-cohort", Purpose: purposeTreatment, Category: catVitals,
		Version: "vLarge", Fields: []FieldName{fieldHeart, fieldPhone}, Subjects: subjects,
	}
	t.Logf("【输入】大批量 %d 主体，worker=%d，字段=%v", n, batchWorkers, req.Fields)
	t0 := time.Now()
	resp := g.BatchAccess(req)
	t.Logf("【判定】耗时 %v 汇总=%+v", time.Since(t0), resp.Summary)

	if resp.Rejected || resp.Summary.Allowed != n {
		t.Fatalf("大批量应全部放行: rejected=%v summary=%+v", resp.Rejected, resp.Summary)
	}
	if len(resp.Outcomes) != n {
		t.Fatalf("结果丢失: want=%d got=%d", n, len(resp.Outcomes))
	}
	// 顺序/数据归属/脱敏全部核对
	for i, o := range resp.Outcomes {
		wantSubj := SubjectID(fmt.Sprintf("subj-%03d", i))
		if o.Index != i || o.Subject != wantSubj {
			t.Fatalf("下标 %d 错配: got=%s", i, o.Subject)
		}
		wantHeart := "7" + fmt.Sprintf("%02d", i)
		if o.Record[fieldHeart] != wantHeart {
			t.Fatalf("主体 %s 数据串位: heart=%q want=%q", o.Subject, o.Record[fieldHeart], wantHeart)
		}
		if o.Record[fieldPhone] == "139"+fmt.Sprintf("%08d", i) {
			t.Fatalf("主体 %s 手机号未脱敏", o.Subject)
		}
	}
	// 审计：n 条主体记录 + 1 条汇总；主体记录下标唯一覆盖 0..n-1
	recs := audit.ListByBatch(resp.BatchID)
	if len(recs) != n+1 {
		t.Fatalf("批次审计丢失: want=%d got=%d", n+1, len(recs))
	}
	idxSeen := make(map[int]bool, n)
	heads := 0
	for _, r := range recs {
		if r.IsBatchHead {
			heads++
			continue
		}
		if idxSeen[r.SubjectIndex] {
			t.Fatalf("审计下标重复（错配/覆盖）: %d", r.SubjectIndex)
		}
		idxSeen[r.SubjectIndex] = true
		if r.SubjectID != subjects[r.SubjectIndex] {
			t.Fatalf("审计主体与下标错配: idx=%d subject=%s", r.SubjectIndex, r.SubjectID)
		}
		if r.PolicyVersion != "vLarge" || !r.Decision.Allowed {
			t.Fatalf("审计结论异常: %+v", r)
		}
	}
	if heads != 1 || len(idxSeen) != n {
		t.Fatalf("批次汇总数=%d，覆盖主体下标=%d", heads, len(idxSeen))
	}
}

// TestConcurrentBatchesIdempotent：多个批次并发提交，其中同一幂等键被多 goroutine 同时重跑，
// 只能有一次实际处理，审计不重复、不错位
func TestConcurrentBatchesIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	g, _, audit := newBatchFixture(t, now)

	base := BatchRequest{
		Entry: "ward-round", IdempotencyKey: "shared-key",
		Purpose: purposeTreatment, Category: catVitals,
		Fields:   []FieldName{fieldHeart},
		Subjects: []SubjectID{subjAlice, subjCarol, subjDave},
	}
	const callers = 30
	var wg sync.WaitGroup
	wg.Add(callers)
	results := make([]BatchResponse, callers)
	t0 := time.Now()
	for c := 0; c < callers; c++ {
		c := c
		go func() {
			defer wg.Done()
			results[c] = g.BatchAccess(base)
		}()
	}
	wg.Wait()
	t.Logf("【输入】%d 个 goroutine 并发重跑同一幂等键，耗时 %v", callers, time.Since(t0))

	var firstID string
	for i, r := range results {
		if r.BatchID == "" {
			t.Fatal("调用者拿到空结果")
		}
		if i == 0 {
			firstID = r.BatchID
		} else if r.BatchID != firstID {
			t.Fatalf("并发重跑必须复用同一批次: %s vs %s", r.BatchID, firstID)
		}
	}
	// 只有 3 主体 + 1 汇总 = 4 条审计，证明没有重复处理/重复审计
	if audit.Len() != 4 {
		t.Fatalf("同一幂等键并发重跑只能产生一次审计: got=%d", audit.Len())
	}
	if len(audit.ListByBatch(firstID)) != 4 {
		t.Fatal("批次内审计记录数量异常")
	}
	t.Logf("【判定】实际只处理 1 个批次 %s，审计=%d 条（无重复返回/重复审计）", firstID, audit.Len())
}
