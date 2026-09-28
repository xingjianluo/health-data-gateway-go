# 本地健康数据访问网关（Go）

用本地存储与授权记录模拟受保护健康数据的访问网关。所有访问入口（临床 UI、移动端、批量导出、研究 API 等）
共用同一套「同意校验 → 数据最小化 → 标识脱敏 → 审计落盘」流水线，保证**相同输入在任何入口下得到相同、可复现的结论**。

在单主体访问之上，网关另外提供**批量访问层**（病区查房、科研队列等一次面向多个数据主体的场景），
不另起炉灶，而是对每个主体复用同一条单主体流水线。

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

## 4. 批量访问（病区查房 / 科研队列）

批量访问不是重做一套，而是在 `Gateway.Access` 之上再加一层编排（`Gateway.BatchAccess`）：
一个批次对**同一个访问用途、同一个数据类别、同一组请求字段**下的多个数据主体，
逐个复用单主体流水线，并把整批结果与每个主体的结论关联起来。

### 4.1 独立判定，互不拖垮

- 每个主体**独立同意判定、独立数据读取、独立最小化脱敏、独立写一条审计**。
- 某人被拒绝、降级或字段不可用，只影响他自己，不会拖垮整批，也不会把 A 的数据串到 B。
- 每人的状态三选一：`allowed`（完整放行）/ `denied`（拒绝，不返回数据）/ `degraded`（放行但有字段被降级跳过），
  并携带互斥的拒绝/降级原因与可读依据。
- 返回的 `Outcomes` 与请求 `Subjects` **顺序严格一致**（按稳定下标槽位输出，与并发完成先后无关），
  另有 `Summary` 给出整批 `total / allowed / denied / degraded` 汇总。

### 4.2 同一批固定口径

- 批次入口只取**一次判断时刻**、只解析**一次策略版本**，之后所有主体都在这同一口径下判定，
  不会一边处理一边换版本/换时刻。
- 不指定 `Version` 时，整批固定按**提交时刻的最新版本**；处理期间即使发布了新版本，本批也不变。
- 批次提交后发生的同意撤回、过期、策略发布，**不会反过来改写本批已确定的结论**；
  但之后的**新请求**会按新口径判定，**历史回放**也仍还原旧口径（见 4.4）。

### 4.3 批量上限、超限处理与重试幂等

- 单批主体数硬上限 `MaxBatchSubjects = 100`。入口先校验后处理：
  - 空批次 → 整体拒绝 `batch_empty`；
  - 主体数超上限 → 整体拒绝 `batch_too_large`（消息中含实际数量与上限），**不处理任何主体**；
  - 批内主体重复 → 整体拒绝 `batch_duplicate_subject`；
  - 指定策略版本不存在 → 整体拒绝 `policy_version_missing`。
  - 整体拒绝时 `BatchResponse.Rejected=true`、`Outcomes=nil`，但仍写一条批次汇总审计留痕。
- **重试 / 断点重跑幂等**：请求携带 `IdempotencyKey` 时，相同键的重试直接返回首次结论
  （同一 `BatchID`、同一批审计 ID、同一份数据），**不重复判定、不重复读取、不重复写审计**；
  即使多个调用方用同一键并发重跑，也只有一次实际处理。幂等返回的是深拷贝，调用方改结果不影响登记表。
- 单批内以固定数量 worker（`batchWorkers=8`）并发处理，每人写入各自下标槽位；
  大批量、本地大并发下结果不丢、审计不丢、不互相覆盖、不串位。

### 4.4 整批审计与历史回放

- 每个批次写 **1 条批次汇总记录**（`IsBatchHead=true`，`SubjectIndex=-1`，记录输入、口径与整批汇总）
  + **每个主体 1 条独立记录**（带 `BatchID` 与稳定 `SubjectIndex`、状态、返回字段范围、拒绝/降级原因），
  通过 `BatchID` 关联，可用 `AuditLog.ListByBatch` 取回。
- `Gateway.ReplayBatch(batchID)` **只依据历史审计记录**还原当时整批结果：
  按历史 `SubjectIndex` 排序，逐人还原 `allowed/denied/degraded`、拒绝原因与**实际返回字段范围**，
  包括部分成功、拒绝与降级混合的情形。
- 同时按每条记录标注的**当时策略版本 + 当时判断时刻**重跑同意判定做交叉校验（`RecheckMatches` / `AllMatch`）；
  数据层结论（`record_not_found` 等）以历史记录为准、不重新读取当前数据。
  因此现在同意被撤回、数据被删改，都**不会影响历史批次还原**。回放本身不新增审计。

### 4.5 与单主体访问的兼容范围

- 批量层只复用、不修改单主体语义：单主体审计记录的批次字段保持零值，`Access` / `Replay` 行为不变；
  既有单主体用例、策略版本发布与并发写入用例全部继续通过。
- 批量要求“同一用途/类别/字段”；需要不同用途或不同字段集合时，请拆成多个批次。
- 降级开关 `Gateway.Degrade` 对整批统一生效（fail-closed 或字段级 `DegradeSkip`），与单主体访问一致。

## 5. 代码结构

| 文件 | 职责 |
| --- | --- |
| `policy.go` | 同意、脱敏规则、策略快照与不可变版本归档 |
| `decision.go` | 同意校验，产出可区分的拒绝原因与判定依据 |
| `store.go` | 并发安全的本地健康数据存储 |
| `masking.go` | 字段最小化、标识脱敏（fail-closed / 可追溯降级） |
| `audit.go` | 并发安全只追加审计日志，支持按批次 ID 关联查询 |
| `gateway.go` | 统一访问入口 `Access`、历史回放 `Replay`，单主体流水线（固定时刻/批次上下文） |
| `idempotency.go` | 批量请求幂等登记表（重试/断点重跑去重） |
| `batch.go` | 批量访问 `BatchAccess`、批量上限校验、整批口径固定、并发编排与 `ReplayBatch` |

## 6. 验证方法

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

批量访问新增用例：

- `TestBatchMixedSubjectsIndependent` — 混合批次（放行/用途越界/过期/无数据），独立判定、稳定顺序、汇总与独立审计；
- `TestBatchPinnedVersionAndTime` — 整批固定同一判断时刻与策略版本，提交后的撤回不改写本批，但新请求与历史回放正确反映；
- `TestBatchIdempotentRetry` — 相同幂等键多次重试逐字节复用首次结论，不重复处理/读取/审计；
- `TestBatchOverLimitRejected` / `TestBatchEmptyAndDuplicateRejected`
  — 超上限（101 主体）、空批次、批内重复主体的清楚拒绝与留痕，且超限拒绝同样幂等；
- `TestBatchDegradePerSubject` — 批内某人字段缺失走降级、其他人完整放行，状态为 `degraded` 且审计留痕；
- `TestBatchReplayMixedRestoresAll` — 混合批次按历史记录还原全部状态/返回范围/原因，
  提交后撤回、删数据、推进时钟均不污染回放；
- `TestLargeBatchNoLossNoMismatch` — 100 主体并发批量，结果/审计不丢不覆盖、下标与数据归属不错配（`-race`）；
- `TestConcurrentBatchesIdempotent` — 30 goroutine 并发重跑同一幂等键，只处理一次、审计不重复（`-race`）。

每个测试均通过 `t.Logf` 打印【输入】【判定】【依据】【输出】【审计】；
批量用例另用【批量输入】【批量判定】打印整批口径（判断时刻、策略版本）与每个主体的状态、原因及依据，
可用 `go test -v` 直接查看输入数据与判定依据。
