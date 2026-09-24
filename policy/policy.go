// Package policy 定义访问策略：数据类别、字段级别最小化规则、
// 标识脱敏策略，以及"用途 -> 类别"的授权矩阵。
// 策略按版本发布并永久保留，历史决策可按当时版本回放。
package policy

import (
	"errors"
	"sort"
	"time"
)

// DataCategory 健康数据类别。
type DataCategory string

// MaskStrategy 标识字段的生效脱敏策略。
type MaskStrategy string

// Version 策略版本号（语义化版本字符串，按发布时间严格递增）。
type Version string

// FieldRule 描述某个字段在某版本策略下的最小化与脱敏规则。
type FieldRule struct {
	Field      string       // 字段名
	Identifier bool         // 是否为标识类字段（如身份证、手机号、姓名）
	Mask       MaskStrategy // 标识字段生效的脱敏策略；非标识字段通常为 MaskNone
}

// CategoryRule 描述某数据类别下允许的字段及其规则。
type CategoryRule struct {
	Category DataCategory
	Fields   []FieldRule
}

// Policy 一个不可变的策略版本。
type Policy struct {
	Version     Version
	PublishedAt time.Time
	// PurposeGrants: 访问用途 -> 该用途可访问的类别集合
	PurposeGrants map[string]map[DataCategory]bool
	// Categories: 类别 -> 类别字段规则
	Categories map[DataCategory]CategoryRule
}

// Registry 策略版本注册表，保存所有历史版本。
type Registry struct {
	current  Version
	policies map[Version]*Policy
}

// 常见脱敏策略。
const (
	MaskNone    MaskStrategy = "none"    // 不脱敏（仅用于非标识字段）
	MaskRedact  MaskStrategy = "redact"  // 整体抹除，返回固定占位符
	MaskPartial MaskStrategy = "partial" // 局部保留（如手机号保留前3后4）
	MaskHash    MaskStrategy = "hash"    // SHA-256 哈希
)

// 错误。
var (
	ErrPolicyNotFound = errors.New("policy: version not found")
	ErrNoPolicy       = errors.New("policy: no published policy")
	ErrEmptyVersion   = errors.New("policy: empty version")
	ErrVersionExists  = errors.New("policy: version already published")
	ErrVersionTooOld  = errors.New("policy: version must be newer than current")
)

// NewRegistry 创建空注册表。
func NewRegistry() *Registry {
	return &Registry{policies: map[Version]*Policy{}}
}

// Publish 发布一个新版本。版本不可变，发布时间必须晚于当前版本，
// 以保证"当前版本"即"最新版本"的单调性。
func (r *Registry) Publish(p *Policy) error {
	if p == nil {
		return errors.New("policy: nil policy")
	}
	if p.Version == "" {
		return ErrEmptyVersion
	}
	if _, exists := r.policies[p.Version]; exists {
		return ErrVersionExists
	}
	if cur, ok := r.policies[r.current]; ok && !p.PublishedAt.After(cur.PublishedAt) {
		return ErrVersionTooOld
	}
	cp := clonePolicy(p)
	r.policies[cp.Version] = cp
	r.current = cp.Version
	return nil
}

// Current 返回当前生效版本。
func (r *Registry) Current() (*Policy, error) {
	if r.current == "" {
		return nil, ErrNoPolicy
	}
	return clonePolicy(r.policies[r.current]), nil
}

// Get 按版本号获取策略；v 为空时返回当前版本。
func (r *Registry) Get(v Version) (*Policy, error) {
	if v == "" {
		return r.Current()
	}
	p, ok := r.policies[v]
	if !ok {
		return nil, ErrPolicyNotFound
	}
	return clonePolicy(p), nil
}

// CurrentVersion 返回当前版本号（无策略时为空串）。
func (r *Registry) CurrentVersion() Version { return r.current }

// Versions 返回所有已发布版本（按发布时间升序）。
func (r *Registry) Versions() []Version {
	out := make([]*Policy, 0, len(r.policies))
	for _, p := range r.policies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublishedAt.Before(out[j].PublishedAt) })
	vs := make([]Version, len(out))
	for i, p := range out {
		vs[i] = p.Version
	}
	return vs
}

// PurposeAllows 判断该策略版本下某用途是否可访问某类别。
func (p *Policy) PurposeAllows(purpose string, cat DataCategory) bool {
	cats, ok := p.PurposeGrants[purpose]
	if !ok {
		return false
	}
	return cats[cat]
}

// FieldRule 返回某类别下某字段的规则及是否存在。
func (p *Policy) FieldRule(cat DataCategory, field string) (FieldRule, bool) {
	cr, ok := p.Categories[cat]
	if !ok {
		return FieldRule{}, false
	}
	for _, fr := range cr.Fields {
		if fr.Field == field {
			return fr, true
		}
	}
	return FieldRule{}, false
}

// FieldsFor 返回某类别被授权的全部字段规则。
func (p *Policy) FieldsFor(cat DataCategory) ([]FieldRule, bool) {
	cr, ok := p.Categories[cat]
	if !ok {
		return nil, false
	}
	out := make([]FieldRule, len(cr.Fields))
	copy(out, cr.Fields)
	return out, true
}

func clonePolicy(p *Policy) *Policy {
	cp := &Policy{
		Version:       p.Version,
		PublishedAt:   p.PublishedAt,
		PurposeGrants: make(map[string]map[DataCategory]bool, len(p.PurposeGrants)),
		Categories:    make(map[DataCategory]CategoryRule, len(p.Categories)),
	}
	for purpose, cats := range p.PurposeGrants {
		m := make(map[DataCategory]bool, len(cats))
		for c, v := range cats {
			m[c] = v
		}
		cp.PurposeGrants[purpose] = m
	}
	for c, cr := range p.Categories {
		fs := make([]FieldRule, len(cr.Fields))
		copy(fs, cr.Fields)
		cp.Categories[c] = CategoryRule{Category: cr.Category, Fields: fs}
	}
	return cp
}
