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

## 4. 批量访问（病区查房 / 科研队列等多主体取数）

批量访问不是另一套实现，而是在既有「同意校验 → 最小化 → 脱敏 → 审计」流水线上再加一层
`Gateway.AccessBatch(BatchRequest)`：一次请求按**同一访问用途、同一数据类别、同一字段集合**
对多个数据主体取数，内部对每个主体复用与单主体访问完全相同的处理（`processSubject`）。

### 4.1 使用场景

- 病区查房：一次性拉取某病区多名患者的同类生命体征数据；
- 科研队列：按固定用途（`research`/`treatment`）批量导出队列成员的脱敏字段；
- 批量报表/导出入口。

### 4.2 同一批的口径规则

- **固定判定时刻**：批次提交时取一次时钟作为全批统一的 `EvaluatedAt`，
  全批的同意过期判定用同一时刻，不会处理到一半换时间。
- **固定策略版本**：显式指定 `Version` 时全批用该版本；不指定时在提交时刻解析一次「最新版本」，
  之后整批锁定该快照。批次处理进行中发布的新版本**不会**改变本批任何一个人的结论。
- **结论对事后变化免疫**：批次提交后发生的同意撤回、过期、策略更新，都不会回写本批已确定的结论；
  但之后的新请求与历史回放会正确反映各自口径（新请求走新版本，回放走当时快照）。
- 单主体结果中每个人的 `Decision.PolicyVersion` 与 `Decision.EvaluatedAt` 都相同，可直接核对。

### 4.3 逐主体独立、互不拖垮、互不串数据

- 每个人**独立判定、独立读取、独立最小化与脱敏**：某人被拒绝（同意缺失/撤回/过期/越界/无数据等）、
  被降级（字段缺失被跳过）或字段不可用，只影响他自己，整批其余人照常返回。
- 每个主体的结果状态三选一：`allowed`（完整放行）、`degraded`（降级放行，有字段被跳过）、
  `denied`（拒绝，不返回任何数据），并携带各自的 `Decision.Reason/Basis`。
- 结果按**去重后主体的首次出现顺序**稳定返回（重复主体只处理一次，空主体标识被忽略）；
  并发处理时结果按索引槽位写回，**不会把 A 的数据放进 B 的结果**。
- `BatchResponse` 含整批汇总：`Total/Allowed/Degraded/Denied`。

### 4.4 批量上限与超限处理

- 默认上限 `MaxBatchSubjects = 100`，可用 `Gateway.BatchLimit` 按入口调整（`<=0` 时取默认值）。
- 去重后主体数为 0（空列表或仅空标识）→ 整批 `rejected`，原因 `batch_empty`；
  超过上限 → 整批 `rejected`，原因 `batch_too_large`，依据中写明实际数量与上限。
- 整批拒绝发生在任何主体处理之前：**不读取任何主体数据、不产生逐条审计**，
  但会落一条整批记录（`BatchRecord`，状态 `rejected`），超限拒绝同样可回放、可幂等重试。

### 4.5 重试 / 断点重跑幂等

`BatchRequest.IdempotencyKey` 由调用方提供（如「队列ID+导出日期」）：

- 同键的重试、断点重跑、甚至并发同键请求，**只有一个批次真正执行**，其余等待并复用同一结论；
  返回的 `BatchID`、每个人的结论与返回范围完全一致，重试响应标记 `Cached=true`；
- 不会重复读取、重复返回、重复写逐条审计，也不会产生第二条整批记录或导致记录串位；
- 不带幂等键的请求每次都是新批次（适用于允许重复发起的实时查询）。

### 4.6 审计与历史回放

- **两层审计、可互相关联**：
  - 整批记录 `BatchRecord`（`BatchLog`）：记录整批输入、统一版本/时刻、整批结论与每人的
    `状态/判定依据/实际返回范围(AuditID)`，提交后即**不可变快照**；
  - 每人一条既有格式的 `AuditRecord`（`AuditLog`），新增 `BatchID` 关联整批、`Degraded` 标记降级。
    `AuditLog.ListByBatch(batchID)` 可取回某批的全部逐条记录；单主体访问 `BatchID=0`，不与批次混淆。
- `Gateway.ReplayBatch(batchID)` 直接按当时落盘的不可变整批快照还原结果，
  **包括部分成功、每个人的拒绝/降级原因与实际返回范围**，不受当前同意状态或最新策略影响。
- 并发/大批量下：整批 ID、逐条审计 ID 都在锁内分配，记录不丢失、不覆盖、不串位（测试配合 `-race`）。

### 4.7 与单主体访问的兼容范围

- 判定原因、脱敏动作、降级语义、策略版本规则与单主体 `Access` 完全一致；
  同一主体在批量内与单独访问得到相同的结论和脱敏结果。
- `Access` / `Replay`、策略发布（`PolicyArchive.Put`）、既有审计行为均保持不变；
  `AuditRecord` 仅新增字段（零值即旧语义），旧用例不受影响。

## 5. 代码结构

| 文件 | 职责 |
| --- | --- |
| `policy.go` | 同意、脱敏规则、策略快照与不可变版本归档 |
| `decision.go` | 同意校验（含固定时刻/固定快照的 `DecideAt`），产出可区分的拒绝原因与判定依据 |
| `store.go` | 并发安全的本地健康数据存储 |
| `masking.go` | 字段最小化、标识脱敏（fail-closed / 可追溯降级，降级时记录跳过字段） |
| `audit.go` | 并发安全只追加审计日志（逐条 `AuditLog` + 整批 `BatchLog` 幂等登记与不可变快照） |
| `gateway.go` | 统一访问入口 `Access`、抽出的单主体处理 `processSubject` 与历史回放 `Replay` |
| `batch.go` | 批量访问 `AccessBatch`、整批汇总、容量控制、幂等与整批回放 `ReplayBatch` |

## 6. 验证方法

```bash
go build ./...
go vet ./...
go test -race -count=1 -v ./...
```

既有测试覆盖（不回归）：

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

本轮新增批量测试：

- `TestBatchMixedResults` — **混合批次/批次内主体状态不同**：放行、降级、三类拒绝并存，
  去重保序、独立脱敏、数据不串位、汇总与逐条审计关联正确；
- `TestBatchRetryIdempotent` — **重试幂等**：撤回并发版后同键断点重跑仍返回首批结论（`Cached`），
  不重复读取/审计/落整批记录，而新请求正确反映新口径；
- `TestBatchReplayConsistent` — **历史回放一致性**：撤回全部同意并发布新版本后，
  `ReplayBatch` 仍逐字节还原当时的部分成功/拒绝/降级与返回范围，并与逐条审计互相印证；
- `TestBatchOverLimitAndEmpty` — **批量上限与超限处理**：超上限/空批整批拒绝、
  不读数据不写逐条审计、拒绝重试也幂等；达上限正常处理；
- `TestBatchConcurrentAudit` — **并发审计**：40 批 × 6 主体并发，整批/逐条记录不丢失、
  不覆盖、不错配、主体不串位（配合 `-race`）；
- `TestBatchConcurrentSameKey` — **同键并发**：30 个同键并发恰好执行一次，其余全部命中同一缓存；
- `TestBatchCompatibleWithSingleAccess` — **与单主体兼容**：同主体批量内外结论/脱敏一致，
  两类审计互不污染，单主体回放不回归。

每个测试均通过 `t.Logf` 打印【输入】【判定】【依据】【输出】【审计】/【整批】【主体】，
可用 `go test -v` 直接查看批量输入、每人的判定依据、实际返回范围与拒/降级原因。
