package gateway

import (
	"sync"
	"time"
)

// SubjectID 数据主体标识
type SubjectID string

// Purpose 访问用途
type Purpose string

// Category 健康数据类别
type Category string

// FieldName 数据字段名
type FieldName string

// Consent 数据主体授予的同意记录
type Consent struct {
	SubjectID  SubjectID
	Purposes   []Purpose   // 授权用途
	Categories []Category  // 授权数据类别
	Fields     []FieldName // 授权字段（数据最小化白名单）
	GrantedAt  time.Time
	ExpiresAt  time.Time // 零值表示不过期
	Withdrawn  bool      // 是否被撤回
}

// MaskAction 标识类字段的脱敏动作
type MaskAction string

const (
	MaskNone    MaskAction = "none"
	MaskRedact  MaskAction = "redact"  // 整值抹除
	MaskPartial MaskAction = "partial" // 局部保留（如手机号前 3 后 4）
	MaskHash    MaskAction = "hash"    // 哈希
)

// MaskingRule 单个标识字段的生效脱敏策略
type MaskingRule struct {
	Field  FieldName
	Action MaskAction
}

// Policy 某一版本的完整策略快照：同意集合 + 脱敏规则
type Policy struct {
	Version     string
	Consents    map[SubjectID]Consent
	Identifiers []FieldName // 标识类字段清单：出现在此但 Masking 无规则视为策略无法匹配
	Masking     map[FieldName]MaskingRule
	CreatedAt   time.Time
}

// PolicyArchive 策略版本归档，支持按版本读取以回放历史结论
type PolicyArchive struct {
	mu       sync.RWMutex
	versions map[string]Policy
	order    []string
}

func NewPolicyArchive() *PolicyArchive {
	return &PolicyArchive{versions: make(map[string]Policy)}
}

// CloneConsent 返回同意记录的深拷贝，避免外部切片被共享修改
func CloneConsent(c Consent) Consent {
	c.Purposes = append([]Purpose(nil), c.Purposes...)
	c.Categories = append([]Category(nil), c.Categories...)
	c.Fields = append([]FieldName(nil), c.Fields...)
	return c
}

func clonePolicy(p Policy) Policy {
	cp := Policy{
		Version:     p.Version,
		Consents:    make(map[SubjectID]Consent, len(p.Consents)),
		Identifiers: append([]FieldName(nil), p.Identifiers...),
		Masking:     make(map[FieldName]MaskingRule, len(p.Masking)),
		CreatedAt:   p.CreatedAt,
	}
	for k, v := range p.Consents {
		cp.Consents[k] = CloneConsent(v)
	}
	for k, v := range p.Masking {
		cp.Masking[k] = v
	}
	return cp
}

// Put 归档一个策略版本。同版本号重复写入会被拒绝，保证历史快照不可变。
func (a *PolicyArchive) Put(p Policy) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.versions[p.Version]; ok {
		return
	}
	a.versions[p.Version] = clonePolicy(p)
	a.order = append(a.order, p.Version)
}

// Get 按版本号读取策略快照（返回副本）
func (a *PolicyArchive) Get(version string) (Policy, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	p, ok := a.versions[version]
	if !ok {
		return Policy{}, false
	}
	return clonePolicy(p), true
}

// Latest 返回最近归档的策略版本（返回副本）
func (a *PolicyArchive) Latest() (Policy, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.order) == 0 {
		return Policy{}, false
	}
	p := a.versions[a.order[len(a.order)-1]]
	return clonePolicy(p), true
}
