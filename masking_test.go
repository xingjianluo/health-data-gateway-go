package gateway

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMaskActions(t *testing.T) {
	m := NewMinimizer()
	auth := []FieldName{fieldName, fieldPhone, fieldHeart}
	ids := []FieldName{fieldName, fieldPhone}
	rules := map[FieldName]MaskingRule{
		fieldName:  {Field: fieldName, Action: MaskRedact},
		fieldPhone: {Field: fieldPhone, Action: MaskPartial},
	}
	rec := Record{fieldName: "Alice Wang", fieldPhone: "13812345678", fieldHeart: "72"}

	logTestInput(t, "record=%v authorized=%v identifiers=%v rules=%v", rec, auth, ids, rules)
	res, err := m.Apply(rec, auth, ids, rules)
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	t.Logf("【判定】%v notes=%v", res.Record, res.Notes)

	if res.Record[fieldName] != "***REDACTED***" {
		t.Fatalf("redact 错误: %q", res.Record[fieldName])
	}
	if !strings.HasPrefix(res.Record[fieldPhone], "138") || !strings.HasSuffix(res.Record[fieldPhone], "5678") {
		t.Fatalf("partial 应保留前3后4: %q", res.Record[fieldPhone])
	}
	if res.Record[fieldHeart] != "72" {
		t.Fatalf("非标识字段不应改动: %q", res.Record[fieldHeart])
	}

	// hash 动作
	rules[fieldName] = MaskingRule{Field: fieldName, Action: MaskHash}
	res2, err := m.Apply(rec, auth, ids, rules)
	if err != nil || !strings.HasPrefix(res2.Record[fieldName], "sha256:") {
		t.Fatalf("hash 动作错误: %+v err=%v", res2.Record, err)
	}
}

func TestIdentifierWithoutPolicyRejected(t *testing.T) {
	m := NewMinimizer()
	// phone 是标识字段但无规则
	_, err := m.Apply(
		Record{fieldName: "Alice", fieldPhone: "138"},
		[]FieldName{fieldName, fieldPhone},
		[]FieldName{fieldName, fieldPhone},
		map[FieldName]MaskingRule{fieldName: {Action: MaskRedact}},
	)
	var me *MinimizeError
	if !errors.As(err, &me) || !errors.Is(me.Err, ErrMaskPolicyMissing) {
		t.Fatalf("应返回策略无法匹配错误, got=%v", err)
	}
	if me.Field != fieldPhone {
		t.Fatalf("错误应定位字段: %s", me.Field)
	}
	t.Logf("【判定】标识字段无策略被拒绝: %v", err)
}

func TestPolicyArchiveImmutableAndVersioned(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	archive, v1, _ := buildPolicies(now)

	got, ok := archive.Get("v1")
	if !ok {
		t.Fatal("v1 应可读取")
	}
	// 外部修改拿到的副本，不应污染归档
	got.Consents[subjAlice] = Consent{Withdrawn: true}
	got.Identifiers[0] = "hacked"
	again, _ := archive.Get("v1")
	if again.Consents[subjAlice].Withdrawn {
		t.Fatal("归档策略必须不可变")
	}
	if again.Identifiers[0] != v1.Identifiers[0] {
		t.Fatal("归档标识符清单必须不可变")
	}

	// 重复 Put 同一版本应被忽略
	archive.Put(Policy{Version: "v1", CreatedAt: now})
	p, _ := archive.Get("v1")
	if _, exists := p.Consents[subjAlice]; !exists {
		t.Fatal("重复归档不得覆盖历史快照")
	}
}
