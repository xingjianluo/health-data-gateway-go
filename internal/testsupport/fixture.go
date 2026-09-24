// Package testsupport 构造确定性的测试夹具：
// 两个策略版本、若干同意记录与本地健康数据。
package testsupport

import (
	"time"

	"github.com/xingjianluo/health-data-gateway-go/consent"
	"github.com/xingjianluo/health-data-gateway-go/policy"
	"github.com/xingjianluo/health-data-gateway-go/storage"
)

const (
	// 用途
	PurposeCare      = "care"     // 诊疗
	PurposeResearch  = "research" // 科研
	PurposeMarketing = "marketing"

	// 类别
	CatDemographics policy.DataCategory = "demographics"
	CatLabs         policy.DataCategory = "labs"
	CatConditions   policy.DataCategory = "conditions"
)

// 版本号。
const (
	V1 policy.Version = "v1.0.0"
	V2 policy.Version = "v2.0.0"
)

// ReferenceTime 测试基准时间：2026-01-15 12:00:00 UTC。
func ReferenceTime() time.Time {
	return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
}

// fieldRulesV1 字段级最小化与脱敏规则。
var demographicsFields = []policy.FieldRule{
	{Field: "name", Identifier: true, Mask: policy.MaskPartial},
	{Field: "id_card", Identifier: true, Mask: policy.MaskRedact},
	{Field: "phone", Identifier: true, Mask: policy.MaskPartial},
	{Field: "address", Identifier: false, Mask: policy.MaskNone},
}

var labsFields = []policy.FieldRule{
	{Field: "glucose", Identifier: false, Mask: policy.MaskNone},
	{Field: "blood_pressure", Identifier: false, Mask: policy.MaskNone},
	{Field: "note", Identifier: false, Mask: policy.MaskNone},
}

// NewRegistry 构造含 v1/v2 两个版本的策略注册表。
// v1: care 可访问三类；research 仅可访问 labs。
// v2: research 额外获得 demographics（用于回放对比）；
//
//	并为 labs 新增 hba1c 字段；发布时间晚于 v1。
func NewRegistry() *policy.Registry {
	reg := policy.NewRegistry()

	v1 := &policy.Policy{
		Version:     V1,
		PublishedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PurposeGrants: map[string]map[policy.DataCategory]bool{
			PurposeCare:      {CatDemographics: true, CatLabs: true, CatConditions: true},
			PurposeResearch:  {CatLabs: true},
			PurposeMarketing: {},
		},
		Categories: map[policy.DataCategory]policy.CategoryRule{
			CatDemographics: {Category: CatDemographics, Fields: demographicsFields},
			CatLabs:         {Category: CatLabs, Fields: labsFields},
			CatConditions:   {Category: CatConditions, Fields: []policy.FieldRule{{Field: "diagnosis", Mask: policy.MaskNone}}},
		},
	}
	_ = reg.Publish(v1)

	labsV2 := append([]policy.FieldRule{}, labsFields...)
	labsV2 = append(labsV2, policy.FieldRule{Field: "hba1c", Mask: policy.MaskNone})
	v2 := &policy.Policy{
		Version:     V2,
		PublishedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PurposeGrants: map[string]map[policy.DataCategory]bool{
			PurposeCare:      {CatDemographics: true, CatLabs: true, CatConditions: true},
			PurposeResearch:  {CatLabs: true, CatDemographics: true},
			PurposeMarketing: {},
		},
		Categories: map[policy.DataCategory]policy.CategoryRule{
			CatDemographics: {Category: CatDemographics, Fields: demographicsFields},
			CatLabs:         {Category: CatLabs, Fields: labsV2},
			CatConditions:   {Category: CatConditions, Fields: []policy.FieldRule{{Field: "diagnosis", Mask: policy.MaskNone}}},
		},
	}
	_ = reg.Publish(v2)
	return reg
}

// Subjects 测试主体。
const (
	SubAlice   = "alice" // 有效同意（care+research）
	SubBob     = "bob"   // 同意已过期
	SubCarol   = "carol" // 同意已撤回
	SubDave    = "dave"  // 同意用途受限（仅 care）
	SubNoGrant = "erin"  // 从无同意记录
	SubFrank   = "frank" // 记录缺字段
)

// NewConsentStore 构造确定性同意存储。
func NewConsentStore() *consent.MemoryStore {
	st := consent.NewMemoryStore()
	t := ReferenceTime()

	_ = st.Save(&consent.Grant{
		ID: "g-alice", SubjectID: SubAlice,
		Categories: []policy.DataCategory{CatDemographics, CatLabs, CatConditions},
		Purposes:   []string{PurposeCare, PurposeResearch},
		ValidFrom:  t.AddDate(-1, 0, 0), ValidUntil: t.AddDate(1, 0, 0),
		Status: consent.StatusActive,
	})
	_ = st.Save(&consent.Grant{
		ID: "g-bob", SubjectID: SubBob,
		Categories: []policy.DataCategory{CatDemographics, CatLabs},
		Purposes:   []string{PurposeCare},
		ValidFrom:  t.AddDate(-2, 0, 0), ValidUntil: t.AddDate(-1, 0, 0), // 已过期
		Status: consent.StatusActive,
	})
	_ = st.Save(&consent.Grant{
		ID: "g-carol", SubjectID: SubCarol,
		Categories: []policy.DataCategory{CatDemographics, CatLabs},
		Purposes:   []string{PurposeCare},
		ValidFrom:  t.AddDate(-1, 0, 0), ValidUntil: t.AddDate(1, 0, 0),
		Status: consent.StatusWithdrawn,
	})
	_ = st.Save(&consent.Grant{
		ID: "g-dave", SubjectID: SubDave,
		Categories: []policy.DataCategory{CatDemographics, CatLabs},
		Purposes:   []string{PurposeCare}, // 无 research
		ValidFrom:  t.AddDate(-1, 0, 0), ValidUntil: t.AddDate(1, 0, 0),
		Status: consent.StatusActive,
	})
	_ = st.Save(&consent.Grant{
		ID: "g-frank", SubjectID: SubFrank,
		Categories: []policy.DataCategory{CatLabs},
		Purposes:   []string{PurposeCare},
		ValidFrom:  t.AddDate(-1, 0, 0), ValidUntil: t.AddDate(1, 0, 0),
		Status: consent.StatusActive,
	})
	return st
}

// NewDataStore 构造本地健康数据。
func NewDataStore() *storage.Store {
	s := storage.NewStore()
	s.Seed(
		storage.Record{SubjectID: SubAlice, Category: CatDemographics, Data: map[string]string{
			"name": "张三", "id_card": "110101199001011234",
			"phone": "13812345678", "address": "北京市海淀区中关村1号",
		}},
		storage.Record{SubjectID: SubAlice, Category: CatLabs, Data: map[string]string{
			"glucose": "5.6", "blood_pressure": "120/80", "note": "空腹",
		}},
		storage.Record{SubjectID: SubBob, Category: CatLabs, Data: map[string]string{
			"glucose": "6.1", "blood_pressure": "130/85",
		}},
		storage.Record{SubjectID: SubCarol, Category: CatDemographics, Data: map[string]string{
			"name": "Carol", "id_card": "310101198505054321", "phone": "13900000000",
		}},
		storage.Record{SubjectID: SubDave, Category: CatDemographics, Data: map[string]string{
			"name": "Dave", "id_card": "440101199203035678", "phone": "13700001111",
		}},
		storage.Record{SubjectID: SubFrank, Category: CatLabs, Data: map[string]string{
			// 故意缺少 blood_pressure 与 note
			"glucose": "7.2",
		}},
	)
	return s
}
