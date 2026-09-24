package gateway

import (
	"testing"
	"time"
)

// 带可控时钟的 Decider，便于构造过期场景
func deciderWithClock(a *PolicyArchive, now time.Time) *Decider {
	d := NewDecider(a)
	d.clock = func() time.Time { return now }
	return d
}

func TestConsentMissing(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	archive, _, _ := buildPolicies(now)
	d := deciderWithClock(archive, now)

	logTestInput(t, "subject=bob(无同意) purpose=%s category=%s version=v1", purposeTreatment, catVitals)
	got := d.Decide(subjBob, purposeTreatment, catVitals, "v1")
	logDecision(t, got)

	if got.Allowed {
		t.Fatal("无同意记录时必须拒绝")
	}
	assertReason(t, got, ReasonConsentMissing)
}

func TestConsentExpired(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	archive, _, _ := buildPolicies(now)
	// 单独放入一个已过期同意的版本 vExp
	expired := Policy{
		Version: "vExp",
		Consents: map[SubjectID]Consent{
			subjAlice: {
				SubjectID:  subjAlice,
				Purposes:   []Purpose{purposeTreatment},
				Categories: []Category{catVitals},
				ExpiresAt:  time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC),
			},
		},
		CreatedAt: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC),
	}
	archive.Put(expired)
	d := deciderWithClock(archive, now)

	logTestInput(t, "subject=alice purpose=%s category=%s version=vExp 同意已于 2026-09-23 过期", purposeTreatment, catVitals)
	got := d.Decide(subjAlice, purposeTreatment, catVitals, "vExp")
	logDecision(t, got)

	if got.Allowed {
		t.Fatal("同意过期时必须拒绝")
	}
	assertReason(t, got, ReasonConsentExpired)
}

func TestConsentWithdrawn(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	archive, _, _ := buildPolicies(now)
	d := deciderWithClock(archive, now)

	logTestInput(t, "subject=alice purpose=%s category=%s version=v2(同意已撤回)", purposeTreatment, catVitals)
	got := d.Decide(subjAlice, purposeTreatment, catVitals, "v2")
	logDecision(t, got)

	if got.Allowed {
		t.Fatal("同意撤回后必须拒绝")
	}
	assertReason(t, got, ReasonConsentWithdrawn)
}

func TestPurposeOutOfScope(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	archive, _, _ := buildPolicies(now)
	d := deciderWithClock(archive, now)

	logTestInput(t, "subject=alice purpose=%s(未授权) category=%s version=v1", purposeResearch, catVitals)
	got := d.Decide(subjAlice, purposeResearch, catVitals, "v1")
	logDecision(t, got)

	if got.Allowed {
		t.Fatal("用途越界必须拒绝")
	}
	assertReason(t, got, ReasonPurposeOutOfScope)
}

func TestCategoryOutOfScope(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	archive, _, _ := buildPolicies(now)
	d := deciderWithClock(archive, now)

	logTestInput(t, "subject=alice purpose=%s category=%s(未授权) version=v1", purposeTreatment, catMental)
	got := d.Decide(subjAlice, purposeTreatment, catMental, "v1")
	logDecision(t, got)

	if got.Allowed {
		t.Fatal("类别越界必须拒绝")
	}
	assertReason(t, got, ReasonCategoryOutOfScope)
}

func TestAllowHappyPath(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	archive, _, _ := buildPolicies(now)
	d := deciderWithClock(archive, now)

	logTestInput(t, "subject=alice purpose=%s category=%s version=v1(长期有效)", purposeTreatment, catVitals)
	got := d.Decide(subjAlice, purposeTreatment, catVitals, "v1")
	logDecision(t, got)

	if !got.Allowed {
		t.Fatalf("授权范围内应放行：%s", got.Basis)
	}
}

func TestRejectReasonsAreDistinct(t *testing.T) {
	// 拒绝原因集合必须两两可区分
	reasons := []DenyReason{
		ReasonConsentMissing,
		ReasonConsentExpired,
		ReasonConsentWithdrawn,
		ReasonPurposeOutOfScope,
		ReasonCategoryOutOfScope,
	}
	seen := map[DenyReason]bool{}
	for _, r := range reasons {
		if seen[r] {
			t.Fatalf("拒绝原因重复: %s", r)
		}
		seen[r] = true
	}
}
