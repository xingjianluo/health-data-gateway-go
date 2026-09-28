package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// 脱敏与最小化阶段的可区分错误
var (
	ErrFieldMissing      = errors.New("authorized field missing from record")
	ErrMaskPolicyMissing = errors.New("identifier field has no matching mask policy")
	ErrMaskActionUnknown = errors.New("unknown mask action")
)

// MinimizeError 携带失败字段，便于审计记录定位问题
type MinimizeError struct {
	Field FieldName
	Err   error
}

func (e *MinimizeError) Error() string {
	return fmt.Sprintf("字段 %s: %s", e.Field, e.Err.Error())
}

func (e *MinimizeError) Unwrap() error { return e.Err }

// MinimizeResult 最小化与脱敏后的结果
type MinimizeResult struct {
	Record  Record
	Notes   []string
	Skipped []FieldName // 降级模式下被跳过（未返回）的授权字段；为空表示未发生降级
}

// Minimizer 执行字段最小化与标识脱敏
type Minimizer struct{}

func NewMinimizer() *Minimizer {
	return &Minimizer{}
}

// Apply 仅输出授权字段，并对标识字段按策略脱敏。
// 任何异常（字段缺失、标识字段无匹配策略、未知动作）都返回错误且不输出任何数据，
// 保证不会静默返回原始数据。
func (m *Minimizer) Apply(rec Record, authorized []FieldName, identifiers []FieldName,
	rules map[FieldName]MaskingRule) (MinimizeResult, error) {

	isIdentifier := make(map[FieldName]bool, len(identifiers))
	for _, f := range identifiers {
		isIdentifier[f] = true
	}

	out := make(Record, len(authorized))
	var notes []string
	for _, f := range authorized {
		raw, present := rec[f]
		if !present {
			// fail-closed：被授权字段在记录中缺失，拒绝整体返回
			return MinimizeResult{}, &MinimizeError{Field: f, Err: ErrFieldMissing}
		}
		if !isIdentifier[f] {
			out[f] = raw
			continue
		}
		rule, ok := rules[f]
		if !ok {
			// 标识字段没有匹配的脱敏策略，不能原文返回
			return MinimizeResult{}, &MinimizeError{Field: f, Err: ErrMaskPolicyMissing}
		}
		masked, err := maskValue(raw, rule.Action)
		if err != nil {
			return MinimizeResult{}, &MinimizeError{Field: f, Err: err}
		}
		out[f] = masked
		notes = append(notes, fmt.Sprintf("字段 %s 按动作 %s 脱敏", f, rule.Action))
	}
	return MinimizeResult{Record: out, Notes: notes}, nil
}

// DegradeApply 降级模式：跳过有问题的字段（缺失字段、无策略标识字段），
// 其余授权字段正常输出，并把跳过原因记录在 Notes 中，保证可追溯。
func (m *Minimizer) DegradeApply(rec Record, authorized []FieldName, identifiers []FieldName,
	rules map[FieldName]MaskingRule) MinimizeResult {

	isIdentifier := make(map[FieldName]bool, len(identifiers))
	for _, f := range identifiers {
		isIdentifier[f] = true
	}

	out := make(Record, len(authorized))
	var notes []string
	var skipped []FieldName
	for _, f := range authorized {
		raw, present := rec[f]
		if !present {
			notes = append(notes, fmt.Sprintf("字段 %s 缺失，降级跳过", f))
			skipped = append(skipped, f)
			continue
		}
		if !isIdentifier[f] {
			out[f] = raw
			continue
		}
		rule, ok := rules[f]
		if !ok {
			notes = append(notes, fmt.Sprintf("标识字段 %s 无匹配脱敏策略，降级跳过（不返回原文）", f))
			skipped = append(skipped, f)
			continue
		}
		masked, err := maskValue(raw, rule.Action)
		if err != nil {
			notes = append(notes, fmt.Sprintf("字段 %s 脱敏失败（%s），降级跳过", f, err.Error()))
			skipped = append(skipped, f)
			continue
		}
		out[f] = masked
		notes = append(notes, fmt.Sprintf("字段 %s 按动作 %s 脱敏", f, rule.Action))
	}
	return MinimizeResult{Record: out, Notes: notes, Skipped: skipped}
}

func maskValue(v string, action MaskAction) (string, error) {
	switch action {
	case MaskNone:
		return v, nil
	case MaskRedact:
		return "***REDACTED***", nil
	case MaskHash:
		sum := sha256.Sum256([]byte(v))
		return "sha256:" + hex.EncodeToString(sum[:])[:16], nil
	case MaskPartial:
		return partialMask(v), nil
	default:
		return "", fmt.Errorf("%w: %s", ErrMaskActionUnknown, action)
	}
}

// partialMask 保留首尾少量字符，中间用 * 替代；短串全部抹除
func partialMask(v string) string {
	r := []rune(v)
	n := len(r)
	switch {
	case n == 0:
		return ""
	case n <= 2:
		return "**"
	case n <= 6:
		return string(r[:1]) + "**"
	default:
		return string(r[:3]) + "****" + string(r[n-4:])
	}
}
