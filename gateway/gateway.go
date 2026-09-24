// Package gateway 是健康数据访问网关的统一门面。
// 不同访问入口（直接访问、代客查询）都必须经由 Access 走同一条
// "同意校验 -> 策略授权 -> 字段授权 -> 最小化脱敏 -> 审计" 链路，
// 从而保证结论一致、可解释、可按策略版本回放。
package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xingjianluo/health-data-gateway-go/audit"
	"github.com/xingjianluo/health-data-gateway-go/consent"
	"github.com/xingjianluo/health-data-gateway-go/masking"
	"github.com/xingjianluo/health-data-gateway-go/policy"
	"github.com/xingjianluo/health-data-gateway-go/storage"
)

// Request 一次健康数据访问请求。
type Request struct {
	Actor     string // 调用方/入口标识
	SubjectID string // 数据主体
	Purpose   string // 访问用途
	Category  policy.DataCategory
	Fields    []string // 显式请求字段；nil 表示授权字段全集
	// At 决策时刻；零值表示当前时间（测试可注入）。
	At time.Time
	// PolicyVersion 指定决策依据版本；空值表示当前生效版本。
	PolicyVersion policy.Version
}

// Response 访问结果。拒绝时 Data 为 nil。
type Response struct {
	Allowed      bool
	Reason       consent.Reason
	Detail       string
	PolicyVer    policy.Version
	AccessID     string
	AuditSeq     int64
	Data         map[string]string
	Warnings     []masking.Warning
	DataAuditSeq int64 // 数据读取审计序号；拒绝时为 0
}

// Gateway 访问网关，聚合全部依赖。
type Gateway struct {
	reg     *policy.Registry
	consent consent.Store
	data    *storage.Store
	audit   *audit.Store
	mode    masking.StrictMode
}

// Option 构造可选项。
type Option func(*Gateway)

// WithStrictMode 设置字段缺失处理模式（默认降级并留痕）。
func WithStrictMode(m masking.StrictMode) Option {
	return func(g *Gateway) { g.mode = m }
}

// New 创建网关。
func New(reg *policy.Registry, consents consent.Store, data *storage.Store, audits *audit.Store, opts ...Option) *Gateway {
	g := &Gateway{
		reg:     reg,
		consent: consents,
		data:    data,
		audit:   audits,
		mode:    masking.ModeDegrade,
	}
	for _, o := range opts {
		o(g)
	}
	return g
}

// AccessDirect 入口一：数据主体/调用方直接访问。
// 与代客入口走完全相同的决策链路，仅 Actor 前缀不同。
func (g *Gateway) AccessDirect(req Request) (*Response, error) {
	req.Actor = "direct:" + req.Actor
	return g.Access(req)
}

// AccessOnBehalf 入口二：第三方代客查询（如应用持用途访问）。
func (g *Gateway) AccessOnBehalf(req Request) (*Response, error) {
	req.Actor = "onbehalf:" + req.Actor
	return g.Access(req)
}

// Access 统一访问入口。
func (g *Gateway) Access(req Request) (*Response, error) {
	at := req.At
	if at.IsZero() {
		at = time.Now()
	}
	accessID := newAccessID()

	resp := &Response{AccessID: accessID}

	// 1) 解析策略版本（决策必须绑定一个确定的、可回放的版本）
	pol, err := g.reg.Get(req.PolicyVersion)
	if err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			return g.deny(resp, req, at, consent.ReasonPolicyVersionMissing,
				fmt.Sprintf("策略版本 %q 不存在，无法形成可回放决策", req.PolicyVersion)), nil
		}
		if errors.Is(err, policy.ErrNoPolicy) {
			return g.deny(resp, req, at, consent.ReasonPolicyVersionMissing,
				"注册表中尚无任何已发布策略"), nil
		}
		return nil, err
	}
	resp.PolicyVer = pol.Version

	// 2) 同意校验（缺失/过期/撤回/用途越界等原因由 consent 包区分）
	v := consent.Evaluate(g.consent, req.SubjectID, req.Purpose, req.Category, at)
	if !v.Allowed {
		return g.deny(resp, req, at, v.Reason, v.Detail), nil
	}

	// 3) 策略矩阵：用途 -> 类别
	if !pol.PurposeAllows(req.Purpose, req.Category) {
		return g.deny(resp, req, at, consent.ReasonPolicyDenies,
			fmt.Sprintf("策略版本 %s 未授权用途 %q 访问类别 %q",
				pol.Version, req.Purpose, req.Category)), nil
	}

	// 4) 字段授权：显式请求字段必须是策略授权字段的子集
	rules, ok := pol.FieldsFor(req.Category)
	if !ok {
		return g.deny(resp, req, at, consent.ReasonMaskFailure,
			fmt.Sprintf("策略版本 %s 中类别 %q 无字段规则，无法匹配脱敏策略",
				pol.Version, req.Category)), nil
	}
	authorized := map[string]bool{}
	for _, fr := range rules {
		authorized[fr.Field] = true
	}
	for _, f := range req.Fields {
		if !authorized[f] {
			return g.deny(resp, req, at, consent.ReasonFieldUnauthorized,
				fmt.Sprintf("字段 %q 不在策略版本 %s 对类别 %q 的授权字段集合内",
					f, pol.Version, req.Category)), nil
		}
	}

	// 5) 读取原始数据（网关只在通过全部决策后触碰受保护数据）
	rec, err := g.data.Get(req.SubjectID, req.Category)
	if err != nil {
		if errors.Is(err, storage.ErrRecordNotFound) {
			return g.deny(resp, req, at, consent.ReasonFieldMissing,
				fmt.Sprintf("存储中不存在主体 %s 类别 %q 的原始记录", req.SubjectID, req.Category)), nil
		}
		return nil, err
	}

	// 6) 最小化 + 标识脱敏（任何失败显式拒绝，绝不回退原始数据）
	res, err := masking.Apply(pol, req.Category, rec.Data, masking.Options{
		RequestedFields: req.Fields,
		Mode:            g.mode,
	})
	if err != nil {
		return g.deny(resp, req, at, mapMaskError(err),
			fmt.Sprintf("最小化/脱敏失败，拒绝返回数据：%v", err)), nil
	}

	// 7) 写"决策允许"审计
	dec := g.audit.Append(audit.Entry{
		At:        at,
		AccessID:  accessID,
		Kind:      audit.KindDecision,
		Actor:     req.Actor,
		SubjectID: req.SubjectID,
		Purpose:   req.Purpose,
		Category:  req.Category,
		PolicyVer: pol.Version,
		Allowed:   true,
		Reason:    consent.ReasonNone,
		Detail:    v.Detail + "；策略矩阵授权通过；字段授权与脱敏策略匹配通过",
	})
	resp.AuditSeq = dec.Seq

	// 8) 写"数据读取"审计（实际返回字段与降级痕迹）
	fieldNames := make([]string, 0, len(res.Fields))
	for f := range res.Fields {
		fieldNames = append(fieldNames, f)
	}
	sort.Strings(fieldNames)
	warns := make([]string, len(res.Warnings))
	for i, w := range res.Warnings {
		warns[i] = fmt.Sprintf("%s: %s", w.Field, w.Reason)
	}
	drd := g.audit.Append(audit.Entry{
		At:        at,
		AccessID:  accessID,
		Kind:      audit.KindDataRead,
		Actor:     req.Actor,
		SubjectID: req.SubjectID,
		Purpose:   req.Purpose,
		Category:  req.Category,
		PolicyVer: pol.Version,
		Allowed:   true,
		Fields:    fieldNames,
		Warnings:  warns,
		Detail:    fmt.Sprintf("返回 %d 个最小化字段，%d 条降级记录", len(fieldNames), len(warns)),
	})
	resp.DataAuditSeq = drd.Seq

	resp.Allowed = true
	resp.Reason = consent.ReasonNone
	resp.Detail = dec.Detail
	resp.Data = res.Fields
	resp.Warnings = res.Warnings
	return resp, nil
}

// deny 写一条拒绝决策审计并构造拒绝响应；任何拒绝路径都不读取/返回数据。
func (g *Gateway) deny(resp *Response, req Request, at time.Time, r consent.Reason, detail string) *Response {
	var ver policy.Version
	if p, err := g.reg.Get(req.PolicyVersion); err == nil {
		ver = p.Version
	} else {
		ver = req.PolicyVersion // 版本缺失时也原样留痕
	}
	e := g.audit.Append(audit.Entry{
		At:        at,
		AccessID:  resp.AccessID,
		Kind:      audit.KindDecision,
		Actor:     req.Actor,
		SubjectID: req.SubjectID,
		Purpose:   req.Purpose,
		Category:  req.Category,
		PolicyVer: ver,
		Allowed:   false,
		Reason:    r,
		Detail:    detail,
	})
	resp.Allowed = false
	resp.Reason = r
	resp.Detail = detail
	resp.AuditSeq = e.Seq
	resp.PolicyVer = ver
	return resp
}

func mapMaskError(err error) consent.Reason {
	switch {
	case errors.Is(err, masking.ErrUnsupportedMask), errors.Is(err, masking.ErrCategoryNotInPolicy):
		return consent.ReasonMaskFailure
	case errors.Is(err, masking.ErrFieldMissing):
		return consent.ReasonFieldMissing
	case errors.Is(err, masking.ErrFieldUnauthorized):
		return consent.ReasonFieldUnauthorized
	default:
		return consent.ReasonMaskFailure
	}
}

// ReplayResult 回放结论。
type ReplayResult struct {
	PolicyVer        policy.Version
	Verdict          consent.Verdict
	MatchedAuditSeqs []int64
	// Consistent 回放结论是否与历史审计完全一致（允许性 + 拒绝原因）。
	Consistent bool
	ReplaySeq  int64
}

// Replay 依据某次历史访问记录上标注的策略版本，在相同输入（主体/用途/类别/
// 判定时刻）下重新推导结论，并与当时审计比对。回放本身也写审计。
func (g *Gateway) Replay(accessID string, actor string, at time.Time) (*ReplayResult, error) {
	dec, ok := g.audit.LastDecision(accessID)
	if !ok {
		return nil, fmt.Errorf("gateway: access id %q not found in audit", accessID)
	}

	pol, err := g.reg.Get(dec.PolicyVer)
	if err != nil {
		// 即便版本缺失也要留痕
		v := consent.Verdict{Allowed: false, Reason: consent.ReasonPolicyVersionMissing,
			Detail: fmt.Sprintf("回放失败：策略版本 %q 已不存在", dec.PolicyVer)}
		e := g.audit.Append(audit.Entry{
			At: at, AccessID: accessID, Kind: audit.KindReplay, Actor: actor,
			SubjectID: dec.SubjectID, Purpose: dec.Purpose, Category: dec.Category,
			PolicyVer: dec.PolicyVer, Allowed: false, Reason: v.Reason,
			Detail: v.Detail, Replayed: true,
		})
		return &ReplayResult{PolicyVer: dec.PolicyVer, Verdict: v, Consistent: false, ReplaySeq: e.Seq}, nil
	}

	// 用历史时刻 at = dec.At 重放同意校验（保证过期/撤回的时间语义可复现）
	v := consent.Evaluate(g.consent, dec.SubjectID, dec.Purpose, dec.Category, dec.At)

	// 再叠加策略矩阵与字段维度（决策审计只记录允许性与原因，这里复算核心判定）
	if v.Allowed && !pol.PurposeAllows(dec.Purpose, dec.Category) {
		v = consent.Verdict{Allowed: false, Reason: consent.ReasonPolicyDenies,
			Detail: "回放：策略矩阵未授权"}
	}

	consistent := v.Allowed == dec.Allowed && v.Reason == dec.Reason
	notes := []string{
		fmt.Sprintf("历史结论 allowed=%v reason=%q（策略 %s，判定时刻 %s）",
			dec.Allowed, dec.Reason, dec.PolicyVer, dec.At.Format(time.RFC3339)),
		fmt.Sprintf("回放结论 allowed=%v reason=%q", v.Allowed, v.Reason),
	}
	if consistent {
		notes = append(notes, "比对一致：历史结论可复现")
	} else {
		notes = append(notes, "比对不一致：当前同意/策略状态与历史不符（历史记录仍以原始审计为准）")
	}

	e := g.audit.Append(audit.Entry{
		At: at, AccessID: accessID, Kind: audit.KindReplay, Actor: actor,
		SubjectID: dec.SubjectID, Purpose: dec.Purpose, Category: dec.Category,
		PolicyVer: pol.Version, Allowed: v.Allowed, Reason: v.Reason,
		Detail: v.Detail, Warnings: notes, Replayed: true,
	})

	return &ReplayResult{
		PolicyVer:        pol.Version,
		Verdict:          v,
		MatchedAuditSeqs: []int64{dec.Seq},
		Consistent:       consistent,
		ReplaySeq:        e.Seq,
	}, nil
}

func newAccessID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return strings.ToLower(hex.EncodeToString(b[:]))
}
