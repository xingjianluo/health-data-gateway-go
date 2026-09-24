package masking_test

import (
	"errors"
	"strings"
	"testing"

	ts "github.com/xingjianluo/health-data-gateway-go/internal/testsupport"
	"github.com/xingjianluo/health-data-gateway-go/masking"
	"github.com/xingjianluo/health-data-gateway-go/policy"
)

func TestApplyMinimizationAndMask(t *testing.T) {
	reg := ts.NewRegistry()
	pol, _ := reg.Get(ts.V2)
	raw := map[string]string{
		"name": "张三", "id_card": "110101199001011234",
		"phone": "13812345678", "address": "北京市海淀区中关村1号",
		"secret_field": "不得出现", // 非授权字段，即使存在于原始数据也必须被剔除
	}

	res, err := masking.Apply(pol, ts.CatDemographics, raw, masking.Options{Mode: masking.ModeDegrade})
	if err != nil {
		t.Fatalf("预期成功，got error: %v", err)
	}

	t.Logf("输入字段: name/id_card/phone/address/secret_field")
	t.Logf("最小化+脱敏输出: %v", res.Fields)

	// 最小化：非授权字段绝不能出现
	if _, ok := res.Fields["secret_field"]; ok {
		t.Fatal("非授权字段 secret_field 必须被剔除")
	}
	// 脱敏断言
	if res.Fields["id_card"] != masking.RedactedPlaceholder {
		t.Fatalf("id_card 应整体抹除，got %q", res.Fields["id_card"])
	}
	if !strings.HasPrefix(res.Fields["phone"], "138****") {
		t.Fatalf("手机号应保留前3后4，got %q", res.Fields["phone"])
	}
	if res.Fields["name"] == "张三" || res.Fields["name"] == "" {
		t.Fatalf("姓名应局部脱敏而非原样/空值，got %q", res.Fields["name"])
	}
	if res.Fields["address"] != "北京市海淀区中关村1号" {
		t.Fatalf("非标识字段应原样返回，got %q", res.Fields["address"])
	}
}

func TestRequestedFieldSubset(t *testing.T) {
	reg := ts.NewRegistry()
	pol, _ := reg.Get(ts.V1)
	raw := map[string]string{"glucose": "5.6", "blood_pressure": "120/80", "note": "空腹"}

	res, err := masking.Apply(pol, ts.CatLabs, raw, masking.Options{
		RequestedFields: []string{"glucose"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fields) != 1 || res.Fields["glucose"] != "5.6" {
		t.Fatalf("仅应返回 glucose，got %v", res.Fields)
	}
	t.Logf("字段子集请求 [glucose] -> %v", res.Fields)

	// 请求非授权字段必须报错，而不是静默返回
	_, err = masking.Apply(pol, ts.CatLabs, raw, masking.Options{
		RequestedFields: []string{"genome"},
	})
	if !errors.Is(err, masking.ErrFieldUnauthorized) {
		t.Fatalf("越权字段应返回 ErrFieldUnauthorized，got %v", err)
	}
	t.Logf("越权字段 genome 被拒绝: %v", err)
}

func TestMissingFieldDegradeAndDeny(t *testing.T) {
	reg := ts.NewRegistry()
	pol, _ := reg.Get(ts.V1)
	raw := map[string]string{"glucose": "7.2"} // 缺 blood_pressure、note

	// 默认降级：返回已有字段 + Warning，绝不伪造或回退
	res, err := masking.Apply(pol, ts.CatLabs, raw, masking.Options{Mode: masking.ModeDegrade})
	if err != nil {
		t.Fatalf("降级模式不应报错，got %v", err)
	}
	if len(res.Warnings) != 2 {
		t.Fatalf("应有2条降级告警，got %d: %+v", len(res.Warnings), res.Warnings)
	}
	if res.Fields["glucose"] != "7.2" {
		t.Fatalf("已有字段应正常返回，got %v", res.Fields)
	}
	t.Logf("字段缺失降级输出=%v 告警=%+v", res.Fields, res.Warnings)

	// 严格模式：缺失即拒绝
	_, err = masking.Apply(pol, ts.CatLabs, raw, masking.Options{Mode: masking.ModeDeny})
	if !errors.Is(err, masking.ErrFieldMissing) {
		t.Fatalf("严格模式应返回 ErrFieldMissing，got %v", err)
	}
	t.Logf("严格模式字段缺失被拒绝: %v", err)
}

func TestUnsupportedMaskStrategyFailsClosed(t *testing.T) {
	// 构造一个标识字段但脱敏策略为空的策略，验证"无法匹配策略即拒绝"
	pol := &policy.Policy{
		Version: "test-bad",
		Categories: map[policy.DataCategory]policy.CategoryRule{
			ts.CatDemographics: {
				Category: ts.CatDemographics,
				Fields: []policy.FieldRule{
					{Field: "ssn", Identifier: true, Mask: ""}, // 未知策略
				},
			},
		},
	}
	_, err := masking.Apply(pol, ts.CatDemographics,
		map[string]string{"ssn": "secret"}, masking.Options{})
	if !errors.Is(err, masking.ErrUnsupportedMask) {
		t.Fatalf("标识字段无可用脱敏策略必须失败(fail-closed)，got %v", err)
	}
	t.Logf("无匹配脱敏策略时拒绝返回原始数据: %v", err)
}

func TestHashMaskDeterministic(t *testing.T) {
	pol := &policy.Policy{
		Version: "test-hash",
		Categories: map[policy.DataCategory]policy.CategoryRule{
			ts.CatDemographics: policy.CategoryRule{
				Category: ts.CatDemographics,
				Fields:   []policy.FieldRule{{Field: "id", Identifier: true, Mask: policy.MaskHash}},
			},
		},
	}
	r1, _ := masking.Apply(pol, ts.CatDemographics, map[string]string{"id": "ABC-123"}, masking.Options{})
	r2, _ := masking.Apply(pol, ts.CatDemographics, map[string]string{"id": "ABC-123"}, masking.Options{})
	if r1.Fields["id"] != r2.Fields["id"] || !strings.HasPrefix(r1.Fields["id"], "sha256:") {
		t.Fatalf("哈希脱敏应确定且可复现: %q vs %q", r1.Fields["id"], r2.Fields["id"])
	}
	t.Logf("哈希脱敏确定性输出: %s", r1.Fields["id"])
}
