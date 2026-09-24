# 本地健康数据访问网关（Go）

用本地存储与授权记录模拟受保护健康数据的访问网关。所有访问入口（临床 UI、移动端、批量导出、研究 API 等）
共用同一套「同意校验 → 数据最小化 → 标识脱敏 → 审计落盘」流水线，保证**相同输入在任何入口下得到相同、可复现的结论**。

## 1. 同意模型

每个策略版本（`Policy`）包含按数据主体（`SubjectID`）归档的同意记录（`Consent`）：

| 维度 | 说明 |
| --- | --- |
| `Purposes` | 授权访问用途白名单（如 `treatment`、`research`） |
| `Categories` | 授权数据类别白名单（如 `vitals`、`mental_health`） |
| `Fields` | 授权字段白名单，数据最小化的依据 |
| `ExpiresAt` | 过期时间；零值表示长期有效 |
| `Withdrawn` | 是否被撤回 |

`Decider.Decide` 按以下顺序判定，拒绝原因**互斥且可区分**（`Decision.Reason`），并给出人类可读依据（`Decision.Basis`）：

1. `policy_version_missing` — 指定策略版本不存在
2. `consent_missing` — 主体在该版本中没有任何同意记录
3. `consent_withdrawn` — 同意已被撤回
4. `consent_expired` — 当前时间晚于 `ExpiresAt`（依据中打印过期时间与判定时间）
5. `purpose_out_of_scope` — 请求用途不在 `Purposes` 内（用途越界）
6. `category_out_of_scope` — 请求类别不在 `Categories` 内
7. 全部通过 → 放行

数据读取阶段另有两个可区分原因：`record_not_found`（本地无数据）、`fields_not_authorized`（请求字段与白名单交集为空）。

## 2. 数据最小化与标识脱敏

- **最小化**：实际输出字段 = 请求字段 ∩ 同意字段白名单，结果不可能包含未授权字段；
  请求未显式列字段时按白名单整体输出。
- **标识字段**：由策略中的 `Identifiers` 清单显式声明，每条字段匹配一条 `MaskingRule`，支持：
  - `redact`：整值抹除为 `***REDACTED***`
  - `partial`：局部保留（如手机号前 3 后 4，`138****5678`）
  - `hash`：SHA-256 哈希后截断
  - `none`：不脱敏（显式声明）
- **失败不静默**（fail-closed）：被授权字段在记录中缺失（`field missing`）、
  标识字段无匹配策略（`mask policy missing`）、脱敏动作未知时，
  默认整体拒绝（原因 `minimization_failed`），**绝不返回原始数据**。
- **可追溯的降级**：将 `Gateway.Degrade` 设为 `DegradeSkip` 后，问题字段被跳过、
  其余字段正常返回，跳过原因逐条写入审计 `Note`；无策略的标识字段即使降级也不会返回原文。

## 3. 策略版本与历史回放

- `PolicyArchive` 保存不可变版本快照（版本号唯一，重复归档被忽略；`Get` 返回深拷贝，外部无法污染归档）。
- 请求可显式指定 `Version`；不指定时按最新版本判定。
- 每条审计记录（`AuditRecord`）都标注决策时使用的 `PolicyVersion`。
- `Gateway.Replay(auditID)` 读取历史审计记录，并**按记录标注的当时版本**（而非当前最新版本）重新判定，
  因此策略更新（如同意被撤回的 v2）后，v1 时的历史「放行」结论仍可原样复现。
- `AuditLog` 只追加：ID 分配与写入在同一互斥锁内完成，并发下 ID 唯一连续、记录不丢失、不相互覆盖。

## 4. 代码结构

| 文件 | 职责 |
| --- | --- |
| `policy.go` | 同意、脱敏规则、策略快照与不可变版本归档 |
| `decision.go` | 同意校验，产出可区分的拒绝原因与判定依据 |
| `store.go` | 并发安全的本地健康数据存储 |
| `masking.go` | 字段最小化、标识脱敏（fail-closed / 可追溯降级） |
| `audit.go` | 并发安全只追加审计日志 |
| `gateway.go` | 统一访问入口 `Access` 与历史回放 `Replay` |

## 5. 验证方法

```bash
go build ./...
go vet ./...
go test -race -count=1 -v ./...
```

测试覆盖：

- `TestConsentMissing` / `TestConsentExpired` / `TestConsentWithdrawn`
  — 同意缺失、过期、撤回，拒绝原因可区分；
- `TestPurposeOutOfScope` / `TestCategoryOutOfScope` — 用途与类别越界；
- `TestAccessAllowedMinimizedAndMasked` — 最小化与三种脱敏动作生效；
- `TestFieldMissingFailsClosed` — 字段缺失时拒绝且不返回原始数据；
- `TestDegradeSkipsProblemField` — 降级跳过问题字段并在审计留痕；
- `TestPolicyVersionReplay` — 策略更新后按历史版本复现旧结论；
- `TestConcurrentAuditNoLossNoOverwrite` — 50×40 并发写入，审计条数/ID 完整无覆盖（配合 `-race`）；
- `TestDecisionConsistentAcrossEntries` — 四个不同入口下决策与脱敏结果完全一致；
- `TestPolicyArchiveImmutableAndVersioned` — 版本快照不可变、重复归档不覆盖。

每个测试均通过 `t.Logf` 打印【输入】【判定】【依据】【输出】【审计】，
可用 `go test -v` 直接查看输入数据与判定依据。
