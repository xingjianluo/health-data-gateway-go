package policy_test

import (
	"errors"
	"testing"
	"time"

	ts "github.com/xingjianluo/health-data-gateway-go/internal/testsupport"
	"github.com/xingjianluo/health-data-gateway-go/policy"
)

func TestRegistryVersions(t *testing.T) {
	reg := ts.NewRegistry()

	cur, err := reg.Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("当前版本=%s 发布于=%s", cur.Version, cur.PublishedAt.Format(time.RFC3339))
	if cur.Version != ts.V2 {
		t.Fatalf("当前版本应为 v2，got %s", cur.Version)
	}

	// 历史版本永久保留且内容为发布时快照
	v1, err := reg.Get(ts.V1)
	if err != nil {
		t.Fatal(err)
	}
	if v1.PurposeAllows(ts.PurposeResearch, ts.CatDemographics) {
		t.Fatal("v1 不应授权 research 访问 demographics（这是 v2 的变更）")
	}
	if !cur.PurposeAllows(ts.PurposeResearch, ts.CatDemographics) {
		t.Fatal("v2 应已授权 research 访问 demographics")
	}
	t.Logf("v1 research->demographics=false；v2 research->demographics=true（版本差异保留可回放）")

	vs := reg.Versions()
	if len(vs) != 2 || vs[0] != ts.V1 || vs[1] != ts.V2 {
		t.Fatalf("版本按发布时间升序返回错误: %v", vs)
	}

	// 已发布策略不可变：外部修改入参不影响注册表快照
	cur.Categories["hack"] = policy.CategoryRule{}
	again, _ := reg.Get(ts.V2)
	if _, hacked := again.Categories["hack"]; hacked {
		t.Fatal("注册表必须保存不可变快照，不能被外部修改污染")
	}
}

func TestPublishGuards(t *testing.T) {
	reg := ts.NewRegistry()
	// 重复版本号
	err := reg.Publish(&policy.Policy{Version: ts.V1, PublishedAt: time.Now()})
	if !errors.Is(err, policy.ErrVersionExists) {
		t.Fatalf("重复发布应报 ErrVersionExists，got %v", err)
	}
	// 旧发布时间
	err = reg.Publish(&policy.Policy{Version: "v3", PublishedAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)})
	if !errors.Is(err, policy.ErrVersionTooOld) {
		t.Fatalf("早于当前版本发布时间应拒绝，got %v", err)
	}
	// 未知版本
	if _, err := reg.Get("nope"); !errors.Is(err, policy.ErrPolicyNotFound) {
		t.Fatalf("未知版本应报 ErrPolicyNotFound，got %v", err)
	}
}
