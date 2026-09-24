package gateway

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestConcurrentAuditNoLossNoOverwrite(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	g, audit := newFixture(t, now)

	const goroutines = 50
	const perG = 40
	var wg sync.WaitGroup
	wg.Add(goroutines)

	t0 := time.Now()
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				// 交替放行/拒绝请求，两种路径都会写审计
				var purpose Purpose
				if j%2 == 0 {
					purpose = purposeTreatment
				} else {
					purpose = purposeResearch
				}
				g.Access(AccessRequest{
					Entry:    fmt.Sprintf("entry-%d", i),
					Subject:  subjAlice,
					Purpose:  purpose,
					Category: catVitals,
					Fields:   []FieldName{fieldHeart},
					Version:  "v1",
				})
			}
		}()
	}
	wg.Wait()
	t.Logf("【输入】%d 个 goroutine × %d 次并发访问，耗时 %v", goroutines, perG, time.Since(t0))

	want := goroutines * perG
	got := audit.Len()
	t.Logf("【判定】期望审计条数=%d 实际=%d", want, got)
	if got != want {
		t.Fatalf("并发写入审计丢失：want=%d got=%d", want, got)
	}

	// ID 必须唯一且连续 1..want，证明无覆盖
	records := audit.List()
	idSeen := make(map[int64]bool, want)
	for _, r := range records {
		if r.ID < 1 || r.ID > int64(want) {
			t.Fatalf("审计 ID 越界: %d", r.ID)
		}
		if idSeen[r.ID] {
			t.Fatalf("审计 ID 重复（发生覆盖）: %d", r.ID)
		}
		idSeen[r.ID] = true
		if r.PolicyVersion != "v1" {
			t.Fatalf("每条审计都必须标注策略版本: %+v", r)
		}
	}

	var allowed, denied int
	for _, r := range records {
		if r.Decision.Allowed {
			allowed++
		} else {
			denied++
		}
	}
	t.Logf("【统计】放行=%d 拒绝=%d，ID 集合大小=%d", allowed, denied, len(idSeen))
	if allowed != want/2 || denied != want/2 {
		t.Fatalf("放/拒数量异常: allowed=%d denied=%d", allowed, denied)
	}
}

// TestDecisionConsistentAcrossEntries：同意校验与最小化脱敏结论不得因入口不同而不同
func TestDecisionConsistentAcrossEntries(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	g, _ := newFixture(t, now)

	entries := []string{"clinical-ui", "mobile-app", "batch-export", "research-api"}
	var first AccessResponse
	for i, e := range entries {
		req := AccessRequest{
			Entry: e, Subject: subjAlice, Purpose: purposeTreatment, Category: catVitals,
			Fields: []FieldName{fieldName, fieldPhone, fieldHeart}, Version: "v1",
		}
		logTestInput(t, "入口=%s 请求字段=%v", e, req.Fields)
		resp := g.Access(req)
		logDecision(t, resp.Decision)
		t.Logf("【输出】entry=%s record=%v", e, resp.Record)
		if i == 0 {
			first = resp
			continue
		}
		if resp.Decision.Allowed != first.Decision.Allowed ||
			resp.Decision.Reason != first.Decision.Reason {
			t.Fatalf("入口 %s 与首个入口的决策不一致", e)
		}
		for k, v := range first.Record {
			if resp.Record[k] != v {
				t.Fatalf("入口 %s 的脱敏结果与首个入口不一致: %s=%q vs %q", e, k, resp.Record[k], v)
			}
		}
	}
}
