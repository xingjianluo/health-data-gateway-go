// Package masking 实现数据最小化（仅保留授权字段）与标识脱敏。
// 关键安全约束：脱敏失败或策略无法匹配时返回错误，绝不静默返回原始数据。
package masking

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/xingjianluo/health-data-gateway-go/policy"
)

// 显式错误，供网关映射为可区分的拒绝原因。
var (
	// ErrCategoryNotInPolicy 策略版本中不存在该类别规则，无法匹配字段策略。
	ErrCategoryNotInPolicy = errors.New("masking: category not defined in policy")
	// ErrFieldUnauthorized 请求字段不在策略授权字段集合内。
	ErrFieldUnauthorized = errors.New("masking: requested field not authorized by policy")
	// ErrUnsupportedMask 标识字段的脱敏策略未知或缺失，无法安全处理。
	ErrUnsupportedMask = errors.New("masking: identifier field without supported mask strategy")
	// ErrFieldMissing 严格模式下被授权字段在原始数据中缺失。
	ErrFieldMissing = errors.New("masking: authorized field missing from source record")
)

// RedactedPlaceholder 整体抹除时返回的固定占位符。
const RedactedPlaceholder = "***REDACTED***"

// Warning 降级记录：被授权字段在数据中缺失时留下可追溯痕迹。
type Warning struct {
	Field  string
	Reason string
}

// Result 最小化+脱敏后的结果。
type Result struct {
	Fields   map[string]string
	Warnings []Warning
}

// StrictMode 字段缺失处理模式。
type StrictMode int

const (
	// ModeDegrade 字段缺失：降级（保留其余字段）并记录 Warning。
	ModeDegrade StrictMode = iota
	// ModeDeny 字段缺失：整体拒绝。
	ModeDeny
)

// Options 最小化处理选项。
type Options struct {
	// RequestedFields 调用方显式请求的字段；nil 表示"授权字段全集"。
	RequestedFields []string
	Mode            StrictMode
}

// Apply 依据策略版本的字段规则，对原始字段做最小化与脱敏。
//
// 处理顺序（确定性）：
//  1. 解析类别字段规则；策略无法匹配 -> ErrCategoryNotInPolicy；
//  2. 校验请求字段必须是授权字段子集，否则 -> ErrFieldUnauthorized；
//  3. 逐个字段处理：缺失字段按模式拒绝(ErrFieldMissing)或降级告警；
//  4. 标识字段必须带受支持的脱敏策略，否则 -> ErrUnsupportedMask；
//  5. 仅输出被授权（且被请求）的字段，其余字段一律不出现。
func Apply(p *policy.Policy, cat policy.DataCategory, raw map[string]string, opts Options) (*Result, error) {
	rules, ok := p.FieldsFor(cat)
	if !ok {
		return nil, fmt.Errorf("%w: category %q", ErrCategoryNotInPolicy, cat)
	}

	ruleByName := make(map[string]policy.FieldRule, len(rules))
	for _, fr := range rules {
		ruleByName[fr.Field] = fr
	}

	// 确定本次实际处理的字段集合（按策略定义顺序，保证可复现）。
	chosen := rules
	if opts.RequestedFields != nil {
		chosen = make([]policy.FieldRule, 0, len(opts.RequestedFields))
		for _, f := range opts.RequestedFields {
			fr, ok := ruleByName[f]
			if !ok {
				return nil, fmt.Errorf("%w: field %q not in authorized fields of category %q",
					ErrFieldUnauthorized, f, cat)
			}
			chosen = append(chosen, fr)
		}
	}

	res := &Result{Fields: map[string]string{}}
	var missing []string

	for _, fr := range chosen {
		val, present := raw[fr.Field]
		if !present {
			switch opts.Mode {
			case ModeDeny:
				missing = append(missing, fr.Field)
			default:
				res.Warnings = append(res.Warnings, Warning{
					Field:  fr.Field,
					Reason: "authorized field missing in source record; degraded by omission",
				})
			}
			continue
		}

		if fr.Identifier {
			masked, err := maskIdentifier(fr.Mask, val)
			if err != nil {
				return nil, fmt.Errorf("field %q: %w", fr.Field, err)
			}
			res.Fields[fr.Field] = masked
			continue
		}

		// 非标识字段：若显式配置了非 none 策略同样执行（防御性，最小化以外不额外暴露）
		if fr.Mask != "" && fr.Mask != policy.MaskNone {
			masked, err := maskIdentifier(fr.Mask, val)
			if err != nil {
				return nil, fmt.Errorf("field %q: %w", fr.Field, err)
			}
			res.Fields[fr.Field] = masked
			continue
		}
		res.Fields[fr.Field] = val
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%w: %v (strict mode)", ErrFieldMissing, missing)
	}

	sort.Slice(res.Warnings, func(i, j int) bool { return res.Warnings[i].Field < res.Warnings[j].Field })
	return res, nil
}

// maskIdentifier 按生效策略处理标识值。未知/空策略一律报错，绝不放行原值。
func maskIdentifier(s policy.MaskStrategy, v string) (string, error) {
	switch s {
	case policy.MaskRedact:
		return RedactedPlaceholder, nil
	case policy.MaskPartial:
		return partialMask(v), nil
	case policy.MaskHash:
		sum := sha256.Sum256([]byte(v))
		return "sha256:" + hex.EncodeToString(sum[:]), nil
	case policy.MaskNone:
		// 显式 none 表示策略明确允许该标识不脱敏（策略是唯一权威）。
		return v, nil
	default:
		return "", fmt.Errorf("%w: strategy %q", ErrUnsupportedMask, s)
	}
}

// partialMask 局部保留：11 位手机号保留前3后4；其余长度保留首字符与尾字符；
// 单字符整体抹除。
func partialMask(v string) string {
	runes := []rune(v)
	n := len(runes)
	switch {
	case n == 11:
		return string(runes[:3]) + "****" + string(runes[7:])
	case n >= 2:
		return string(runes[0]) + "***" + string(runes[n-1])
	default:
		return "*"
	}
}
