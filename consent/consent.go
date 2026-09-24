// Package consent 管理数据主体（subject）的授权记录（同意）。
// 每条同意记录覆盖：数据类别集合、允许用途集合、有效期与状态。
package consent

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/xingjianluo/health-data-gateway-go/policy"
)

// Status 同意记录状态。
type Status string

const (
	StatusActive    Status = "active"    // 有效
	StatusWithdrawn Status = "withdrawn" // 已被数据主体撤回
)

// Reason 拒绝原因码，要求各拒绝场景可区分。
type Reason string

const (
	ReasonNone                 Reason = ""                       // 未拒绝
	ReasonConsentNotFound      Reason = "consent_not_found"      // 无任何同意记录
	ReasonConsentExpired       Reason = "consent_expired"        // 同意已过期（或尚未生效）
	ReasonConsentWithdrawn     Reason = "consent_withdrawn"      // 同意已被撤回
	ReasonPurposeOutOfScope    Reason = "purpose_out_of_scope"   // 同意未覆盖该用途
	ReasonCategoryNotGranted   Reason = "category_not_granted"   // 同意未覆盖该数据类别
	ReasonPolicyDenies         Reason = "policy_denies"          // 策略矩阵未授权该用途访问该类别
	ReasonFieldUnauthorized    Reason = "field_unauthorized"     // 请求字段超出授权字段集合
	ReasonMaskFailure          Reason = "mask_failure"           // 标识脱敏失败 / 策略无法匹配
	ReasonFieldMissing         Reason = "field_missing"          // 严格模式下授权字段在数据中缺失
	ReasonPolicyVersionMissing Reason = "policy_version_missing" // 回放时策略版本不存在
)

// Grant 数据主体给出的一份同意授权。
type Grant struct {
	ID         string
	SubjectID  string
	Categories []policy.DataCategory
	Purposes   []string
	ValidFrom  time.Time
	ValidUntil time.Time // 零值表示长期有效
	Status     Status
}

// Store 同意记录存储。
type Store interface {
	// GrantsFor 返回某主体的全部同意记录（含历史/已撤回）。
	GrantsFor(subjectID string) ([]*Grant, error)
	// Save 写入或更新一条同意记录。
	Save(g *Grant) error
}

// MemoryStore 基于内存的同意存储（并发安全），用于本地模拟。
type MemoryStore struct {
	mu     sync.RWMutex
	grants map[string]*Grant // grantID -> grant
}

// NewMemoryStore 创建空内存同意存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{grants: map[string]*Grant{}}
}

// Save 写入或更新同意记录。
func (m *MemoryStore) Save(g *Grant) error {
	if g == nil || g.ID == "" {
		return errors.New("consent: grant or grant id empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *g
	m.grants[cp.ID] = &cp
	return nil
}

// Withdraw 将一条同意记录标记为撤回。
func (m *MemoryStore) Withdraw(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return ErrGrantNotFound
	}
	g.Status = StatusWithdrawn
	return nil
}

// GrantsFor 返回某主体的全部同意记录。
func (m *MemoryStore) GrantsFor(subjectID string) ([]*Grant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Grant
	for _, g := range m.grants {
		if g.SubjectID == subjectID {
			cp := *g
			out = append(out, &cp)
		}
	}
	return out, nil
}

// Basis 决策依据：命中的同意记录及其覆盖范围说明，可解释用。
type Basis struct {
	GrantID     string
	Categories  []policy.DataCategory
	Purposes    []string
	ValidFrom   string
	ValidUntil  string
	Status      Status
	Explanation string
}

// Verdict 一次同意/授权校验结论。
type Verdict struct {
	Allowed bool
	Reason  Reason
	// Detail 人类可读的判定依据描述。
	Detail string
	// Basis 允许时命中的授权依据；拒绝时可能为空。
	Basis *Basis
}

func (g *Grant) coversCategory(c policy.DataCategory) bool {
	for _, x := range g.Categories {
		if x == c {
			return true
		}
	}
	return false
}

func (g *Grant) coversPurpose(p string) bool {
	for _, x := range g.Purposes {
		if x == p {
			return true
		}
	}
	return false
}

// inWindow 判断 at 是否处于有效期内。零值 ValidFrom 视为不设下限，
// 零值 ValidUntil 视为长期有效。
func (g *Grant) inWindow(at time.Time) bool {
	if !g.ValidFrom.IsZero() && at.Before(g.ValidFrom) {
		return false
	}
	if !g.ValidUntil.IsZero() && at.After(g.ValidUntil) {
		return false
	}
	return true
}

func deny(r Reason, detail string) Verdict {
	return Verdict{Allowed: false, Reason: r, Detail: detail}
}

// Evaluate 根据主体、用途、类别和判定时刻做同意校验。
//
// 拒绝原因的判定优先级（确定性、可复现）：
//  1. 主体无任何同意记录            -> consent_not_found
//  2. 无记录覆盖该数据类别          -> category_not_granted
//  3. 无记录覆盖该用途              -> purpose_out_of_scope
//  4. 覆盖范围的记录全部已撤回      -> consent_withdrawn
//  5. 覆盖范围的有效记录不在有效期  -> consent_expired
//  6. 命中一条 active 且在有效期内  -> 允许
func Evaluate(store Store, subjectID, purpose string, cat policy.DataCategory, at time.Time) Verdict {
	grants, err := store.GrantsFor(subjectID)
	if err != nil {
		return deny(ReasonConsentNotFound, fmt.Sprintf("读取同意记录失败: %v", err))
	}
	if len(grants) == 0 {
		return deny(ReasonConsentNotFound,
			fmt.Sprintf("主体 %s 不存在任何同意记录", subjectID))
	}

	var coversCat, coversPurpose, scoped []*Grant
	for _, g := range grants {
		if g.coversCategory(cat) {
			coversCat = append(coversCat, g)
		}
		if g.coversPurpose(purpose) {
			coversPurpose = append(coversPurpose, g)
		}
		if g.coversCategory(cat) && g.coversPurpose(purpose) {
			scoped = append(scoped, g)
		}
	}

	if len(coversCat) == 0 {
		return deny(ReasonCategoryNotGranted,
			fmt.Sprintf("主体 %s 的 %d 条同意记录均未覆盖数据类别 %q", subjectID, len(grants), cat))
	}
	if len(coversPurpose) == 0 {
		return deny(ReasonPurposeOutOfScope,
			fmt.Sprintf("主体 %s 的同意记录未授予访问用途 %q", subjectID, purpose))
	}
	if len(scoped) == 0 {
		// 类别和用途分别被不同记录覆盖，但没有任何一条同时覆盖二者
		return deny(ReasonPurposeOutOfScope,
			fmt.Sprintf("主体 %s 不存在同时覆盖用途 %q 与类别 %q 的同意记录", subjectID, purpose, cat))
	}

	// 范围匹配的记录中：优先找 active 且在有效期内的
	var activeScoped, withdrawnScoped, expiredScoped []*Grant
	for _, g := range scoped {
		switch {
		case g.Status == StatusWithdrawn:
			withdrawnScoped = append(withdrawnScoped, g)
		case g.Status == StatusActive && g.inWindow(at):
			activeScoped = append(activeScoped, g)
		default:
			expiredScoped = append(expiredScoped, g)
		}
	}

	if len(activeScoped) > 0 {
		g := activeScoped[0]
		return Verdict{
			Allowed: true,
			Reason:  ReasonNone,
			Detail: fmt.Sprintf("命中有效同意 %s：用途 %q、类别 %q 在有效期内（判定时刻 %s）",
				g.ID, purpose, cat, at.Format(time.RFC3339)),
			Basis: basisFrom(g),
		}
	}

	// 无可用授权：范围匹配记录全部撤回 -> withdrawn，否则按过期处理
	if len(withdrawnScoped) == len(scoped) {
		ids := make([]string, len(withdrawnScoped))
		for i, g := range withdrawnScoped {
			ids[i] = g.ID
		}
		return deny(ReasonConsentWithdrawn,
			fmt.Sprintf("覆盖用途 %q 与类别 %q 的同意记录 %v 均已被数据主体撤回", purpose, cat, ids))
	}

	ids := make([]string, len(expiredScoped))
	for i, g := range expiredScoped {
		ids[i] = g.ID
	}
	return deny(ReasonConsentExpired,
		fmt.Sprintf("覆盖用途 %q 与类别 %q 的同意记录 %v 在判定时刻 %s 均不在有效期内（已过期或尚未生效）",
			purpose, cat, ids, at.Format(time.RFC3339)))
}

func basisFrom(g *Grant) *Basis {
	b := &Basis{
		GrantID:    g.ID,
		Categories: append([]policy.DataCategory(nil), g.Categories...),
		Purposes:   append([]string(nil), g.Purposes...),
		Status:     g.Status,
	}
	if !g.ValidFrom.IsZero() {
		b.ValidFrom = g.ValidFrom.Format(time.RFC3339)
	}
	if !g.ValidUntil.IsZero() {
		b.ValidUntil = g.ValidUntil.Format(time.RFC3339)
	}
	b.Explanation = fmt.Sprintf("同意记录 %s 授权用途 %v 访问类别 %v，有效期 %s ~ %s，状态 %s",
		g.ID, g.Purposes, g.Categories, b.ValidFrom, b.ValidUntil, g.Status)
	return b
}

// ErrGrantNotFound 同意记录不存在。
var ErrGrantNotFound = errors.New("consent: grant not found")
