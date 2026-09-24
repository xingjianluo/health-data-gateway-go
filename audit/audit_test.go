package audit_test

import (
	"sync"
	"testing"

	"github.com/xingjianluo/health-data-gateway-go/audit"
)

func TestConcurrentAppendNoLoss(t *testing.T) {
	s := audit.NewStore()

	const goroutines = 50
	const perG = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				s.Append(audit.Entry{
					AccessID: "acc",
					Kind:     audit.KindDecision,
					Actor:    "tester",
					Detail:   "concurrent write",
				})
			}
			_ = g
		}()
	}
	wg.Wait()

	want := goroutines * perG
	all := s.All()
	t.Logf("输入: %d 个 goroutine 各写 %d 条；期望总数 %d，实际 %d", goroutines, perG, want, len(all))
	if len(all) != want {
		t.Fatalf("并发写入丢失：期望 %d 条，实际 %d 条", want, len(all))
	}

	// 序号必须唯一且连续 1..N（无相互覆盖）
	seen := map[int64]bool{}
	var prev int64
	for _, e := range all {
		if seen[e.Seq] {
			t.Fatalf("审计序号发生覆盖/重复: %d", e.Seq)
		}
		seen[e.Seq] = true
		if e.Seq != prev+1 {
			t.Fatalf("序号不连续：%d 之后是 %d", prev, e.Seq)
		}
		prev = e.Seq
	}
	t.Logf("审计序号 1..%d 唯一且连续，无丢失、无覆盖", prev)
}

func TestByAccess(t *testing.T) {
	s := audit.NewStore()
	s.Append(audit.Entry{AccessID: "A", Kind: audit.KindDecision})
	s.Append(audit.Entry{AccessID: "B", Kind: audit.KindDecision})
	s.Append(audit.Entry{AccessID: "A", Kind: audit.KindDataRead})
	a := s.ByAccess("A")
	if len(a) != 2 || a[0].Kind != audit.KindDecision || a[1].Kind != audit.KindDataRead {
		t.Fatalf("ByAccess 应返回 A 的2条有序条目，got %+v", a)
	}
	if _, ok := s.LastDecision("A"); !ok {
		t.Fatal("LastDecision 未找到决策条目")
	}
}
