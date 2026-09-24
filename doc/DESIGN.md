# 设计说明

## 1. 同意模型（consent）

一条同意记录 `consent.Grant` 表示数据主体授予的一份授权：

| 字段 | 含义 |
|---|---|
| `SubjectID` | 数据主体 |
| `Categories` | 授权覆盖的数据类别集合 |
| `Purposes` | 授权允许的访问用途集合 |
| `ValidFrom` / `ValidUntil` | 有效期；`ValidUntil` 零值表示长期有效 |
| `Status` | `active` 或 `withdrawn`（撤回，终态） |

判定时刻 `at` 由调用方（测试/网关）注入，使过期、撤回等时间语义**完全确定、可复现**。

`consent.Evaluate` 按固定优先级给出**可区分**的拒绝原因码：

| 优先级 | 条件 | 原因码 `consent.Reason` |
|---|---|---|
| 1 | 主体没有任何同意记录 | `consent_not_found` |
| 2 | 无任何记录覆盖该数据类别 | `category_not_granted` |
| 3 | 无任何记录覆盖该用途 | `purpose_out_of_scope` |
| 3' | 用途与类别分别被不同记录覆盖，但无一条同时覆盖二者 | `purpose_out_of_scope` |
| 4 | 覆盖该"用途+类别"的记录全部被撤回 | `consent_withdrawn` |
| 5 | 覆盖记录均不在有效期（过期 / 尚未生效） | `consent_expired` |
| 6 | 存在 active 且在有效期内的覆盖记录 | 允许，返回 `Basis` |

- 撤回与过期优先以**撤回**区分（即使已撤回的记录也已过期）。
- 有效期为闭区间：判定时刻恰好等于 `ValidUntil` 仍有效。
- 允许结论携带 `Basis`（命中记录 ID、覆盖类别/用途、有效期、状态与文字说明），即"决策依据可解释"。

网关在同意校验之后还会叠加两道**策略侧**判定：

| 条件 | 原因码 |
|---|---|
| 策略版本的"用途→类别"矩阵未授权 | `policy_denies` |
| 显式请求字段不在策略授权字段集合内 | `field_unauthorized` |
| 请求的策略版本在注册表中不存在 | `policy_version_missing` |

## 2. 数据最小化与标识脱敏（masking）

### 2.1 最小化

策略按 `(版本, 类别)` 声明**授权字段全集**及每个字段的规则 `FieldRule`：

- 调用方不传 `Fields`：输出授权字段全集；
- 调用方传 `Fields`：必须是授权字段的**子集**，越界字段 → `field_unauthorized`，拒绝整个请求；
- 原始数据中任何未被授权的字段一律不进入输出（白名单语义，不是黑名单）。

### 2.2 标识脱敏

`FieldRule.Identifier=true` 的标识字段必须按 `Mask` 策略处理：

| 策略 | 行为 | 示例 |
|---|---|---|
| `redact` | 整体抹除为固定占位符 `***REDACTED***` | 身份证号 |
| `partial` | 局部保留：11 位手机号保留前 3 后 4；其他串保留首尾；单字符抹除 | `13812345678 → 138****5678` |
| `hash` | `sha256:` 前缀 + 十六进制摘要，确定性、可复现 | `id → sha256:4d15…` |
| `none` | 仅当策略**显式**声明不脱敏时放行原值 | 非标识字段默认 |

### 2.3 失败即关闭（fail-closed），绝不静默返回原始数据

- 标识字段的策略未知/为空 → `ErrUnsupportedMask`，拒绝（`mask_failure`）；
- 类别在策略版本中无字段规则 → `ErrCategoryNotInPolicy`，拒绝；
- 脱敏过程任何错误都向上返回，网关以拒绝告终，**不存在"出错就返回原文"的分支**。

### 2.4 字段缺失：拒绝或降级，均留痕

授权字段在原始记录中缺失时，按网关构造的 `StrictMode` 处理：

- `ModeDegrade`（默认）：保留其余字段，缺失字段不出现，并在结果 `Warnings` 与
  `data_read` 审计中记录 `field=<字段>, reason=authorized field missing…`；
- `ModeDeny`：整体拒绝，原因码 `field_missing`。

## 3. 策略版本与历史回放（policy / audit / gateway）

### 3.1 版本化、不可变的策略

- `policy.Registry` 保存全部已发布版本；`Publish` 要求版本号唯一、发布时间严格晚于当前版本；
- 注册表对每个版本保存**深拷贝快照**，`Get/Current` 也返回拷贝，发布后不可被外部改动污染；
- `Get("")` / `Current()` 返回当前生效版本；`Get(v)` 返回任意历史版本。

每个决策（及随后的数据读取）审计条目都标注 `PolicyVer`，记录"当时依据的是哪个版本"。

### 3.2 审计结构与并发安全

每次允许的访问产生两条共享同一 `AccessID` 的条目：

1. `decision`：允许性、拒绝原因码、判定依据文字、策略版本；
2. `data_read`：实际返回字段（排序后）、降级告警。

拒绝访问只产生一条 `decision` 条目，不触碰数据。

`audit.Store` 在**同一把互斥锁**内完成"序号自增 + 追加"，序号在 `1..N` 上唯一且连续。
`go test -race` 下 50 goroutine × 100 条写入验证无丢失、无覆盖、无竞态。

### 3.3 回放（Gateway.Replay）

`Replay(accessID, actor, at)`：

1. 从审计中取出该访问的原始 `decision` 条目（请求快照：主体/用途/类别/判定时刻/策略版本）；
2. 用**条目上标注的历史策略版本**（而非当前版本）与**历史判定时刻**重新推导同意与策略结论；
3. 与历史审计的 `Allowed + Reason` 逐项比对，给出 `Consistent`；
4. 写一条 `kind=replay`、`replayed=true` 的审计，记录历史结论、回放结论与比对说明。

夹具中 `v1 → v2` 的演化为标准回放示例：

- v1：`research` 只能访问 `labs`，访问 `demographics` 被拒（`policy_denies`）；
- v2：`research` 获得 `demographics` 授权，相同输入变为允许；
- 对 v1 的历史访问做回放：尽管"当前策略"已允许，回放仍按 v1 **复现拒绝**，`Consistent=true`。

回放回答的问题是："**按当时的策略版本和当时的时间点，这个结论是否成立且可复现**"；
历史审计本身不可变，即使当前同意状态变化（事后撤回），原始记录仍保持原样。

## 4. 验证方法

```bash
# 全量单测（-v 日志打印每个用例的输入与判定依据）
go test ./... -v

# 竞态检测（并发审计、并发网关访问）
go test -race ./...

# 静态检查
go vet ./...
```

测试覆盖矩阵：

| 场景 | 测试位置 |
|---|---|
| 同意缺失 / 过期（含有效期边界）/ 撤回（含运行时撤回）/ 用途越界 / 类别越界 | `consent/consent_test.go` |
| 策略版本差异、快照不可变、发布保护 | `policy/policy_test.go` |
| 最小化剔除未授权字段、三类脱敏、字段子集越权、字段缺失降级与严格拒绝、无匹配策略 fail-closed、哈希确定性 | `masking/masking_test.go` |
| 50×100 并发审计写入：总数完整、序号唯一连续 | `audit/audit_test.go` |
| 两类入口结论一致、网关级各拒绝原因可区分、字段缺省降级留痕、v1/v2 版本回放复现、40 路并发网关审计 | `gateway/gateway_test.go` |

所有测试用例通过 `internal/testsupport` 共享确定性夹具（固定基准时间 `2026-01-15T12:00:00Z`），
不依赖墙钟时间，结论可重复。
