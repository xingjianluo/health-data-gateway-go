package consent_test

import (
	"github.com/xingjianluo/health-data-gateway-go/consent"
	"testing"
	"time"

	ts "github.com/xingjianluo/health-data-gateway-go/internal/testsupport"
	"github.com/xingjianluo/health-data-gateway-go/policy"
)

// logVerdict 打印测试输入与判定依据（需求：单测日志需打印输入与判定依据）。
func logVerdict(t *testing.T, subject, purpose string, cat policy.DataCategory, at time.Time, v consent.Verdict) {
	t.Helper()
	t.Logf("输入: subject=%q purpose=%q category=%q at=%s", subject, purpose, cat, at.Format(time.RFC3339))
	t.Logf("判定: allowed=%v reason=%q", v.Allowed, v.Reason)
	t.Logf("依据: %s", v.Detail)
	if v.Basis != nil {
		t.Logf("命中同意: %s", v.Basis.Explanation)
	}
}

func TestEvaluate(t *testing.T) {
	st := ts.NewConsentStore()
	at := ts.ReferenceTime()

	cases := []struct {
		name    string
		subject string
		purpose string
		cat     policy.DataCategory
		wantOK  bool
		wantR   consent.Reason
	}{
		{"有效同意-诊疗-人口学", ts.SubAlice, ts.PurposeCare, ts.CatDemographics, true, consent.ReasonNone},
		{"有效同意-科研-化验", ts.SubAlice, ts.PurposeResearch, ts.CatLabs, true, consent.ReasonNone},
		{"无同意记录", ts.SubNoGrant, ts.PurposeCare, ts.CatLabs, false, consent.ReasonConsentNotFound},
		{"同意已过期", ts.SubBob, ts.PurposeCare, ts.CatLabs, false, consent.ReasonConsentExpired},
		{"同意已撤回", ts.SubCarol, ts.PurposeCare, ts.CatDemographics, false, consent.ReasonConsentWithdrawn},
		{"用途越界-仅诊疗同意做科研", ts.SubDave, ts.PurposeResearch, ts.CatDemographics, false, consent.ReasonPurposeOutOfScope},
		{"类别越界-alice无其他类别", ts.SubAlice, ts.PurposeCare, policy.DataCategory("genetics"), false, consent.ReasonCategoryNotGranted},
		{"营销用途从未授权", ts.SubAlice, ts.PurposeMarketing, ts.CatLabs, false, consent.ReasonPurposeOutOfScope},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := consent.Evaluate(st, c.subject, c.purpose, c.cat, at)
			logVerdict(t, c.subject, c.purpose, c.cat, at, v)
			if v.Allowed != c.wantOK {
				t.Fatalf("allowed=%v, want %v", v.Allowed, c.wantOK)
			}
			if v.Reason != c.wantR {
				t.Fatalf("reason=%q, want %q", v.Reason, c.wantR)
			}
			if c.wantOK && v.Basis == nil {
				t.Fatal("允许时必须返回可解释的授权依据 Basis")
			}
		})
	}
}

// TestExpiryBoundary 验证有效期边界的可复现判定。
func TestExpiryBoundary(t *testing.T) {
	st := ts.NewConsentStore()
	grants, _ := st.GrantsFor(ts.SubBob)
	var g *consent.Grant
	for _, x := range grants {
		if x.ID == "g-bob" {
			g = x
		}
	}
	// 恰好等于 ValidUntil 仍在窗口内；之后一秒过期
	v := consent.Evaluate(st, ts.SubBob, ts.PurposeCare, ts.CatLabs, g.ValidUntil)
	logVerdict(t, ts.SubBob, ts.PurposeCare, ts.CatLabs, g.ValidUntil, v)
	if !v.Allowed {
		t.Fatalf("有效期截止时刻应视为有效，got reason=%q", v.Reason)
	}
	v = consent.Evaluate(st, ts.SubBob, ts.PurposeCare, ts.CatLabs, g.ValidUntil.Add(time.Second))
	if v.Allowed || v.Reason != consent.ReasonConsentExpired {
		t.Fatalf("截止后应过期，got allowed=%v reason=%q", v.Allowed, v.Reason)
	}
}

// TestWithdrawAtRuntime 运行时撤回后立即生效，且拒绝原因可与过期区分。
func TestWithdrawAtRuntime(t *testing.T) {
	st := ts.NewConsentStore()
	at := ts.ReferenceTime()
	if v := consent.Evaluate(st, ts.SubAlice, ts.PurposeCare, ts.CatLabs, at); !v.Allowed {
		t.Fatal("前置条件：撤回前应允许")
	}
	if err := st.Withdraw("g-alice", at); err != nil {
		t.Fatal(err)
	}
	v := consent.Evaluate(st, ts.SubAlice, ts.PurposeCare, ts.CatLabs, at)
	logVerdict(t, ts.SubAlice, ts.PurposeCare, ts.CatLabs, at, v)
	if v.Allowed || v.Reason != consent.ReasonConsentWithdrawn {
		t.Fatalf("撤回后必须以 consent_withdrawn 拒绝，got %q", v.Reason)
	}
}
