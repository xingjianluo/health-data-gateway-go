package gateway

import "time"

// DenyReason 可区分的拒绝原因
type DenyReason string

const (
	ReasonAllowed              DenyReason = ""
	ReasonConsentMissing       DenyReason = "consent_missing"
	ReasonConsentExpired       DenyReason = "consent_expired"
	ReasonConsentWithdrawn     DenyReason = "consent_withdrawn"
	ReasonPurposeOutOfScope    DenyReason = "purpose_out_of_scope"
	ReasonCategoryOutOfScope   DenyReason = "category_out_of_scope"
	ReasonPolicyVersionMissing DenyReason = "policy_version_missing"
	ReasonRecordNotFound       DenyReason = "record_not_found"
	ReasonFieldsNotAuthorized  DenyReason = "fields_not_authorized"
	ReasonMinimizationFailed   DenyReason = "minimization_failed"
)

// Decision 一次访问的授权结论
type Decision struct {
	Allowed       bool
	Reason        DenyReason
	Basis         string // 人类可读的判定依据
	PolicyVersion string
	EvaluatedAt   time.Time
}

// Decider 基于策略版本执行同意校验
type Decider struct {
	archive *PolicyArchive
	clock   func() time.Time
}

func NewDecider(archive *PolicyArchive) *Decider {
	return &Decider{archive: archive, clock: time.Now}
}

func contains[T ~string](list []T, v T) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Decide 按指定策略版本对访问请求做授权判定。
// version 为空时使用最新版本。各拒绝分支原因互斥、依据可解释。
func (d *Decider) Decide(subject SubjectID, purpose Purpose, category Category, version string) Decision {
	now := d.clock()
	var pol Policy
	var ver string
	var hasPolicy bool
	if version == "" {
		pol, hasPolicy = d.archive.Latest()
		ver = pol.Version
	} else {
		pol, hasPolicy = d.archive.Get(version)
		ver = version
	}
	return d.DecideAt(subject, purpose, category, ver, now, hasPolicy, pol)
}

// DecideAt 在给定的判定时刻、给定策略快照上做授权判定。
// 批量访问用它保证：全批共用同一个 now（同意过期口径一致）、
// 同一份策略快照（批次处理中途发布新版本也不换口径）。
func (d *Decider) DecideAt(subject SubjectID, purpose Purpose, category Category,
	ver string, now time.Time, hasPolicy bool, pol Policy) Decision {
	if !hasPolicy {
		return Decision{
			Allowed:       false,
			Reason:        ReasonPolicyVersionMissing,
			Basis:         "策略版本不存在: " + ver,
			PolicyVersion: ver,
			EvaluatedAt:   now,
		}
	}

	consent, ok := pol.Consents[subject]
	if !ok {
		return Decision{
			Allowed:       false,
			Reason:        ReasonConsentMissing,
			Basis:         "主体 " + string(subject) + " 在策略 " + ver + " 中没有任何同意记录",
			PolicyVersion: ver,
			EvaluatedAt:   now,
		}
	}

	if consent.Withdrawn {
		return Decision{
			Allowed:       false,
			Reason:        ReasonConsentWithdrawn,
			Basis:         "主体 " + string(subject) + " 的同意已被撤回",
			PolicyVersion: ver,
			EvaluatedAt:   now,
		}
	}

	if !consent.ExpiresAt.IsZero() && now.After(consent.ExpiresAt) {
		return Decision{
			Allowed: false,
			Reason:  ReasonConsentExpired,
			Basis: "主体 " + string(subject) + " 的同意已于 " +
				consent.ExpiresAt.Format(time.RFC3339) + " 过期（判定时间 " + now.Format(time.RFC3339) + "）",
			PolicyVersion: ver,
			EvaluatedAt:   now,
		}
	}

	if !contains(consent.Purposes, purpose) {
		return Decision{
			Allowed:       false,
			Reason:        ReasonPurposeOutOfScope,
			Basis:         "用途 " + string(purpose) + " 不在同意授权用途范围内",
			PolicyVersion: ver,
			EvaluatedAt:   now,
		}
	}

	if !contains(consent.Categories, category) {
		return Decision{
			Allowed:       false,
			Reason:        ReasonCategoryOutOfScope,
			Basis:         "数据类别 " + string(category) + " 不在同意授权类别范围内",
			PolicyVersion: ver,
			EvaluatedAt:   now,
		}
	}

	return Decision{
		Allowed: true,
		Reason:  ReasonAllowed,
		Basis: "同意有效：用途 " + string(purpose) + "、类别 " + string(category) +
			" 均在主体 " + string(subject) + " 授权范围内，过期时间 " +
			expireText(consent.ExpiresAt),
		PolicyVersion: ver,
		EvaluatedAt:   now,
	}
}

func expireText(t time.Time) string {
	if t.IsZero() {
		return "无（长期有效）"
	}
	return t.Format(time.RFC3339)
}
