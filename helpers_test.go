package gateway

import (
	"fmt"
	"testing"
	"time"
)

const (
	subjAlice SubjectID = "alice"
	subjBob   SubjectID = "bob"

	purposeTreatment Purpose  = "treatment"
	purposeResearch  Purpose  = "research"
	catVitals        Category = "vitals"
	catMental        Category = "mental_health"

	fieldName    FieldName = "full_name"
	fieldPhone   FieldName = "phone"
	fieldHeart   FieldName = "heart_rate"
	fieldDiag    FieldName = "diagnosis"
	fieldUnknown FieldName = "unknown_field"
)

// logTestInput 统一打印测试输入
func logTestInput(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Logf("【输入】"+format, args...)
}

// logDecision 统一打印判定结论与依据
func logDecision(t *testing.T, d Decision) {
	t.Helper()
	t.Logf("【判定】allowed=%v reason=%q policyVersion=%s\n【依据】%s",
		d.Allowed, string(d.Reason), d.PolicyVersion, d.Basis)
}

// buildPolicies 构造两个策略版本：
// v1（2025-01-01 生效）：alice 同意 treatment+vitals，含手机号脱敏；
// v2（之后更新）：alice 撤回同意。
func buildPolicies(now time.Time) (*PolicyArchive, Policy, Policy) {
	v1 := Policy{
		Version: "v1",
		Consents: map[SubjectID]Consent{
			subjAlice: {
				SubjectID:  subjAlice,
				Purposes:   []Purpose{purposeTreatment},
				Categories: []Category{catVitals},
				Fields:     []FieldName{fieldName, fieldPhone, fieldHeart},
				GrantedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				ExpiresAt:  time.Time{}, // v1 长期有效
			},
		},
		Identifiers: []FieldName{fieldName, fieldPhone},
		Masking: map[FieldName]MaskingRule{
			fieldName:  {Field: fieldName, Action: MaskRedact},
			fieldPhone: {Field: fieldPhone, Action: MaskPartial},
		},
		CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	// v2：alice 的同意被撤回
	aliceV2 := CloneConsent(v1.Consents[subjAlice])
	aliceV2.Withdrawn = true
	v2 := Policy{
		Version:     "v2",
		Consents:    map[SubjectID]Consent{subjAlice: aliceV2},
		Identifiers: append([]FieldName(nil), v1.Identifiers...),
		Masking:     v1.Masking,
		CreatedAt:   now,
	}

	archive := NewPolicyArchive()
	archive.Put(v1)
	archive.Put(v2)
	return archive, v1, v2
}

func seedStore() *HealthStore {
	s := NewHealthStore()
	s.Put(subjAlice, catVitals, Record{
		fieldName:  "Alice Wang",
		fieldPhone: "13812345678",
		fieldHeart: "72",
	})
	return s
}

func assertReason(t *testing.T, d Decision, want DenyReason) {
	t.Helper()
	if d.Reason != want {
		t.Fatalf("拒绝原因不符：got=%q want=%q", d.Reason, want)
	}
}

func dumpAudit(t *testing.T, l *AuditLog) {
	t.Helper()
	for _, r := range l.List() {
		fmt.Printf("【审计#%d】entry=%s subject=%s purpose=%s category=%s version=%s allowed=%v reason=%q returned=%v note=%s\n",
			r.ID, r.Entry, r.SubjectID, r.Purpose, r.Category, r.PolicyVersion,
			r.Decision.Allowed, string(r.Decision.Reason), r.FieldsReturned, r.Note)
	}
}
