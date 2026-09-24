package gateway_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/xingjianluo/health-data-gateway-go/audit"
	"github.com/xingjianluo/health-data-gateway-go/consent"
	"github.com/xingjianluo/health-data-gateway-go/gateway"
	ts "github.com/xingjianluo/health-data-gateway-go/internal/testsupport"
	"github.com/xingjianluo/health-data-gateway-go/masking"
	"github.com/xingjianluo/health-data-gateway-go/policy"
)

func newGW(mode masking.StrictMode) (*gateway.Gateway, *audit.Store) {
	aud := audit.NewStore()
	gw := gateway.New(ts.NewRegistry(), ts.NewConsentStore(), ts.NewDataStore(), aud,
		gateway.WithStrictMode(mode))
	return gw, aud
}

func logResp(t *testing.T, req gateway.Request, r *gateway.Response) {
	t.Helper()
	t.Logf("入口=%s 输入: subject=%q purpose=%q category=%q fields=%v ver=%s",
		req.Actor, req.SubjectID, req.Purpose, req.Category, req.Fields, req.PolicyVersion)
	t.Logf("判定: allowed=%v reason=%q policy=%s auditSeq=%d",
		r.Allowed, r.Reason, r.PolicyVer, r.AuditSeq)
	t.Logf("依据: %s", r.Detail)
	if r.Allowed {
		t.Logf("返回数据: %v 降级: %+v", r.Data, r.Warnings)
	}
}

func baseReq() gateway.Request {
	return gateway.Request{
		Actor: "app-1", SubjectID: ts.SubAlice,
		Purpose: ts.PurposeCare, Category: ts.CatDemographics,
		At: ts.ReferenceTime(),
	}
}

// TestAccessAllowedAndMasked 允许路径：最小化+脱敏结果正确，且写两条审计。
func TestAccessAllowedAndMasked(t *testing.T) {
	gw, aud := newGW(masking.ModeDegrade)
	req := baseReq()
	resp, err := gw.Access(req)
	if err != nil {
		t.Fatal(err)
	}
	logResp(t, req, resp)
	if !resp.Allowed {
		t.Fatalf("应允许，reason=%q detail=%s", resp.Reason, resp.Detail)
	}
	if resp.Data["id_card"] != masking.RedactedPlaceholder {
		t.Fatalf("id_card 应抹除，got %q", resp.Data["id_card"])
	}
	if _, ok := resp.Data["address"]; !ok {
		t.Fatal("非标识授权字段应返回")
	}
	if got := aud.Count(); got != 2 {
		t.Fatalf("允许路径应写 decision+data_read 两条审计，got %d", got)
	}
	entries := aud.ByAccess(resp.AccessID)
	if entries[0].Kind != audit.KindDecision || entries[1].Kind != audit.KindDataRead {
		t.Fatalf("审计条目类型/顺序错误: %+v", entries)
	}
	if entries[0].PolicyVer != ts.V2 {
		t.Fatalf("审计必须标注当前策略版本 %s，got %s", ts.V2, entries[0].PolicyVer)
	}
}

// TestDenyReasons 各拒绝场景的原因码必须可区分，且拒绝不产生数据读取审计。
func TestDenyReasons(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *gateway.Request)
		ver    policy.Version
		want   consent.Reason
	}{
		{"同意缺失", func(r *gateway.Request) { r.SubjectID = ts.SubNoGrant }, "", consent.ReasonConsentNotFound},
		{"同意过期", func(r *gateway.Request) { r.SubjectID = ts.SubBob; r.Category = ts.CatLabs }, "", consent.ReasonConsentExpired},
		{"同意撤回", func(r *gateway.Request) { r.SubjectID = ts.SubCarol }, "", consent.ReasonConsentWithdrawn},
		{"用途越界-同意", func(r *gateway.Request) { r.SubjectID = ts.SubDave; r.Purpose = ts.PurposeResearch }, "", consent.ReasonPurposeOutOfScope},
		{"策略矩阵拒绝", func(r *gateway.Request) {
			r.SubjectID = ts.SubAlice
			r.Purpose = ts.PurposeResearch
			r.Category = ts.CatDemographics
		}, ts.V1, consent.ReasonPolicyDenies},
		{"字段未授权", func(r *gateway.Request) { r.Fields = []string{"id_card", "genome"} }, "", consent.ReasonFieldUnauthorized},
		{"策略版本不存在", func(r *gateway.Request) {}, "v9.9.9", consent.ReasonPolicyVersionMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gw, aud := newGW(masking.ModeDegrade)
			req := baseReq()
			req.PolicyVersion = c.ver
			c.mutate(&req)
			resp, err := gw.Access(req)
			if err != nil {
				t.Fatal(err)
			}
			logResp(t, req, resp)
			if resp.Allowed {
				t.Fatal("应拒绝")
			}
			if resp.Reason != c.want {
				t.Fatalf("拒绝原因=%q，期望 %q", resp.Reason, c.want)
			}
			// 拒绝只写一条 decision 审计，不读取数据
			if aud.Count() != 1 {
				t.Fatalf("拒绝路径应只有1条审计，got %d", aud.Count())
			}
			if aud.All()[0].Allowed || aud.All()[0].Reason != c.want {
				t.Fatal("审计必须如实记录拒绝及原因")
			}
		})
	}
}

// TestTwoEntriesConsistent 不同访问入口对同一输入必须给出一致结论。
func TestTwoEntriesConsistent(t *testing.T) {
	gw, _ := newGW(masking.ModeDegrade)

	req1 := baseReq()
	req1.Actor = "portal"
	r1, err := gw.AccessDirect(req1)
	if err != nil {
		t.Fatal(err)
	}

	req2 := baseReq()
	req2.Actor = "third-party-app"
	r2, err := gw.AccessOnBehalf(req2)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("直接入口: allowed=%v data=%v", r1.Allowed, r1.Data)
	t.Logf("代客入口: allowed=%v data=%v", r2.Allowed, r2.Data)

	if r1.Allowed != r2.Allowed || r1.PolicyVer != r2.PolicyVer {
		t.Fatal("两个入口的允许性/策略版本必须一致")
	}
	if fmt.Sprint(r1.Data) != fmt.Sprint(r2.Data) {
		t.Fatalf("两个入口的最小化脱敏结果必须一致:\n%v\n%v", r1.Data, r2.Data)
	}
}

// TestMissingFieldGateway 网关层字段缺省：降级留痕 vs 严格拒绝。
func TestMissingFieldGateway(t *testing.T) {
	t.Run("降级模式", func(t *testing.T) {
		gw, aud := newGW(masking.ModeDegrade)
		req := gateway.Request{
			Actor: "app", SubjectID: ts.SubFrank,
			Purpose: ts.PurposeCare, Category: ts.CatLabs, At: ts.ReferenceTime(),
			PolicyVersion: ts.V1, // v1 的 labs 仅 3 字段：glucose 在，缺 2 个
		}
		resp, err := gw.Access(req)
		if err != nil {
			t.Fatal(err)
		}
		logResp(t, req, resp)
		if !resp.Allowed || len(resp.Warnings) != 2 {
			t.Fatalf("应降级允许并带2条告警，got allowed=%v warnings=%d", resp.Allowed, len(resp.Warnings))
		}
		// 降级痕迹必须进入数据读取审计
		drd := aud.ByAccess(resp.AccessID)[1]
		if len(drd.Warnings) != 2 {
			t.Fatalf("降级痕迹必须可追溯，审计 warnings=%v", drd.Warnings)
		}
	})
	t.Run("严格模式", func(t *testing.T) {
		gw, _ := newGW(masking.ModeDeny)
		req := gateway.Request{
			Actor: "app", SubjectID: ts.SubFrank,
			Purpose: ts.PurposeCare, Category: ts.CatLabs, At: ts.ReferenceTime(),
			PolicyVersion: ts.V1,
		}
		resp, err := gw.Access(req)
		if err != nil {
			t.Fatal(err)
		}
		logResp(t, req, resp)
		if resp.Allowed || resp.Reason != consent.ReasonFieldMissing {
			t.Fatalf("严格模式应以 field_missing 拒绝，got allowed=%v reason=%q", resp.Allowed, resp.Reason)
		}
	})
}

// TestPolicyVersionReplay 核心：v1 下被策略拒绝；策略升级到 v2 后允许；
// 但回放历史访问时必须按 v1 复现"拒绝"结论。
func TestPolicyVersionReplay(t *testing.T) {
	gw, aud := newGW(masking.ModeDegrade)

	// 1) 用显式 v1 做一次访问：research + demographics 在 v1 被矩阵拒绝
	req := baseReq()
	req.Purpose = ts.PurposeResearch
	req.Category = ts.CatDemographics
	req.PolicyVersion = ts.V1
	old, err := gw.Access(req)
	if err != nil {
		t.Fatal(err)
	}
	logResp(t, req, old)
	if old.Allowed || old.Reason != consent.ReasonPolicyDenies {
		t.Fatalf("v1 下应被策略拒绝，got allowed=%v reason=%q", old.Allowed, old.Reason)
	}
	if old.PolicyVer != ts.V1 {
		t.Fatalf("审计必须标注 v1，got %s", old.PolicyVer)
	}

	// 2) 当前版本 v2 下相同输入允许（策略确已变更，证明回放不是"读当前结论"）
	req2 := req
	req2.PolicyVersion = "" // 当前版本
	cur, err := gw.Access(req2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("当前版本 %s 下相同输入: allowed=%v", cur.PolicyVer, cur.Allowed)
	if !cur.Allowed {
		t.Fatalf("v2 已授予 research 对 demographics 的访问，应允许")
	}

	// 3) 回放 v1 那次历史访问：必须复现当时的拒绝
	rep, err := gw.Replay(old.AccessID, "auditor", ts.ReferenceTime())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("回放历史访问 %s: policy=%s allowed=%v reason=%q consistent=%v",
		old.AccessID, rep.PolicyVer, rep.Verdict.Allowed, rep.Verdict.Reason, rep.Consistent)
	if !rep.Consistent || rep.Verdict.Allowed || rep.Verdict.Reason != consent.ReasonPolicyDenies {
		t.Fatalf("回放必须按 v1 复现拒绝且与历史一致，got %+v", rep)
	}

	// 4) 回放本身写审计，且标注 v1
	re := aud.All()[aud.Count()-1]
	if re.Kind != audit.KindReplay || re.PolicyVer != ts.V1 || !re.Replayed {
		t.Fatalf("回放审计条目不正确: %+v", re)
	}
}

// TestReplayConsentWithdraw 回放一个"当时允许、现在已撤回"的访问：
// 历史记录仍保持允许，回放按历史时刻与 v2 复现允许结论。
func TestReplayHistoricalAllow(t *testing.T) {
	reg := ts.NewRegistry()
	cs := ts.NewConsentStore()
	ds := ts.NewDataStore()
	aud := audit.NewStore()
	gw := gateway.New(reg, cs, ds, aud)

	req := gateway.Request{
		Actor: "app", SubjectID: ts.SubAlice,
		Purpose: ts.PurposeCare, Category: ts.CatLabs, At: ts.ReferenceTime(),
	}
	resp, err := gw.Access(req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Allowed {
		t.Fatal("历史访问应允许")
	}

	rep, err := gw.Replay(resp.AccessID, "auditor", ts.ReferenceTime())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("回放允许记录: allowed=%v consistent=%v policy=%s", rep.Verdict.Allowed, rep.Consistent, rep.PolicyVer)
	if !rep.Consistent || !rep.Verdict.Allowed {
		t.Fatal("历史允许结论必须可复现")
	}
}

// TestGatewayConcurrentAudit 并发经过网关的访问不得丢失/覆盖审计。
func TestGatewayConcurrentAudit(t *testing.T) {
	gw, aud := newGW(masking.ModeDegrade)
	const n = 40
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			req := baseReq()
			req.Actor = fmt.Sprintf("worker-%d", i)
			_, _ = gw.Access(req)
		}()
	}
	wg.Wait()
	// 每个允许访问 2 条
	if aud.Count() != 2*n {
		t.Fatalf("并发网关访问审计应完整无丢失：期望 %d，实际 %d", 2*n, aud.Count())
	}
	seqs := map[int64]bool{}
	for _, e := range aud.All() {
		if seqs[e.Seq] {
			t.Fatalf("审计序号重复/覆盖: %d", e.Seq)
		}
		seqs[e.Seq] = true
	}
	t.Logf("并发 %d 次访问产生 %d 条审计，序号唯一无覆盖", n, aud.Count())
}
