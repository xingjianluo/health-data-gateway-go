package gateway

import (
	"fmt"
	"testing"
	"time"
)

const (
	subjCarol SubjectID = "carol"
	subjDave  SubjectID = "dave"
	subjErin  SubjectID = "erin"
)

// newBatchFixture 构造多主体夹具（初始只归档提交时刻生效的 vBatch；
// “提交后才发布”的 vBatchAfter 由测试按需调用 publishWithdrawnVersion 加入）：
//   - vBatch 版本（提交时刻生效）：
//     alice：treatment+vitals，全字段授权（可放行）
//     carol：仅 research 用途（treatment 越界 -> 拒绝）
//     dave ：treatment+vitals 但同意在 2026-09-25 过期（提交时已过期 -> 拒绝）
//     erin ：treatment+vitals，全字段授权，但本地无数据（record_not_found -> 拒绝）
//   - store 中只放 alice/carol/dave 的数据，erin 故意缺数据
func newBatchFixture(t *testing.T, now time.Time) (*Gateway, *PolicyArchive, *AuditLog) {
	t.Helper()
	base := Policy{
		Version: "vBatch",
		Consents: map[SubjectID]Consent{
			subjAlice: {
				SubjectID:  subjAlice,
				Purposes:   []Purpose{purposeTreatment},
				Categories: []Category{catVitals},
				Fields:     []FieldName{fieldName, fieldPhone, fieldHeart},
				GrantedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			subjCarol: {
				SubjectID:  subjCarol,
				Purposes:   []Purpose{purposeResearch},
				Categories: []Category{catVitals},
				Fields:     []FieldName{fieldName, fieldPhone, fieldHeart},
				GrantedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			subjDave: {
				SubjectID:  subjDave,
				Purposes:   []Purpose{purposeTreatment},
				Categories: []Category{catVitals},
				Fields:     []FieldName{fieldName, fieldPhone, fieldHeart},
				GrantedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				ExpiresAt:  time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
			},
			subjErin: {
				SubjectID:  subjErin,
				Purposes:   []Purpose{purposeTreatment},
				Categories: []Category{catVitals},
				Fields:     []FieldName{fieldName, fieldPhone, fieldHeart},
				GrantedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		Identifiers: []FieldName{fieldName, fieldPhone},
		Masking: map[FieldName]MaskingRule{
			fieldName:  {Field: fieldName, Action: MaskRedact},
			fieldPhone: {Field: fieldPhone, Action: MaskPartial},
		},
		CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}

	archive := NewPolicyArchive()
	archive.Put(base)

	store := NewHealthStore()
	store.Put(subjAlice, catVitals, Record{
		fieldName: "Alice Wang", fieldPhone: "13812345678", fieldHeart: "72",
	})
	store.Put(subjCarol, catVitals, Record{
		fieldName: "Carol Li", fieldPhone: "13911112222", fieldHeart: "68",
	})
	store.Put(subjDave, catVitals, Record{
		fieldName: "Dave Ma", fieldPhone: "13733334444", fieldHeart: "80",
	})
	// erin 不写数据

	audit := NewAuditLog()
	g := New(archive, store, audit)
	g.clock = func() time.Time { return now }
	g.decider.clock = func() time.Time { return now }
	return g, archive, audit
}

// publishWithdrawnVersion 在批次提交之后发布新版本：alice 同意被撤回，其余主体不变
func publishWithdrawnVersion(archive *PolicyArchive, base Policy, publishedAt time.Time) {
	after := Policy{
		Version:     "vBatchAfter",
		Identifiers: append([]FieldName(nil), base.Identifiers...),
		Masking:     base.Masking,
		CreatedAt:   publishedAt,
		Consents:    map[SubjectID]Consent{},
	}
	for k, v := range base.Consents {
		c := CloneConsent(v)
		if k == subjAlice {
			c.Withdrawn = true
		}
		after.Consents[k] = c
	}
	archive.Put(after)
}

func logBatchInput(t *testing.T, req BatchRequest, pinnedVersion string) {
	t.Helper()
	t.Logf("【批量输入】entry=%s 用途=%s 类别=%s 版本=%s 字段=%v 主体(顺序)=%v 幂等键=%q",
		req.Entry, req.Purpose, req.Category, pinnedVersion, req.Fields, req.Subjects, req.IdempotencyKey)
}

func logBatchResult(t *testing.T, resp BatchResponse) {
	t.Helper()
	if resp.Rejected {
		t.Logf("【批量判定】整体拒绝 reason=%q msg=%s batchID=%s", resp.Reason, resp.Message, resp.BatchID)
		return
	}
	t.Logf("【批量判定】batchID=%s 版本=%s 判断时刻=%s 汇总=%+v",
		resp.BatchID, resp.PolicyVersion, resp.EvaluatedAt.Format(time.RFC3339), resp.Summary)
	for _, o := range resp.Outcomes {
		t.Logf("  [%d] 主体=%s 状态=%s reason=%q auditID=%d 返回字段=%v\n      依据=%s",
			o.Index, o.Subject, o.Status, o.Decision.Reason, o.AuditID, fieldNames(o.Record), o.Decision.Basis)
	}
}

func dumpBatchAudit(t *testing.T, audit *AuditLog, batchID string) {
	t.Helper()
	for _, r := range audit.ListByBatch(batchID) {
		head := ""
		if r.IsBatchHead {
			head = " [批次汇总]"
		}
		fmt.Printf("【审计#%d】%s idx=%d subject=%s outcome=%s version=%s allowed=%v reason=%q returned=%v%s\n    note=%s\n",
			r.ID, r.BatchID, r.SubjectIndex, r.SubjectID, r.Outcome, r.PolicyVersion,
			r.Decision.Allowed, r.Decision.Reason, r.FieldsReturned, head, r.Note)
	}
}
