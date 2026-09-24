# 本地健康数据访问网关（Go）

用**本地存储 + 授权记录**模拟受保护健康数据的访问网关。无论调用方从哪个入口
（数据主体直接访问 `AccessDirect` / 第三方代客查询 `AccessOnBehalf`）进入，
都走同一条决策链路，保证：

- 同意校验、策略授权、最小化脱敏的**结论一致且可复现**；
- 拒绝原因**可区分**、决策依据**可解释**；
- 每次决策与数据读取都写**带策略版本的审计**，历史结论可按当时版本**回放**；
- 并发审计写入不丢失、不覆盖。

## 目录结构

| 包 | 职责 |
|---|---|
| `policy` | 策略版本注册表：用途→类别授权矩阵、字段级规则（是否标识、脱敏策略） |
| `consent` | 同意记录存储与校验：缺失/过期/撤回/用途越界/类别越界的可区分判定 |
| `storage` | 本地健康记录存储（内存、并发安全） |
| `masking` | 数据最小化（仅授权字段）+ 标识脱敏（抹除/局部/哈希），失败即拒绝 |
| `audit` | 审计条目存储：互斥锁 + 单调序号，并发安全 |
| `gateway` | 统一门面：决策编排、两个访问入口、按策略版本回放 |
| `internal/testsupport` | 确定性测试夹具（v1/v2 两个策略版本、各类同意与数据） |

## 快速开始

```bash
go build ./...
go vet ./...
go test ./... -v          # 日志中会打印每个用例的"输入"与"判定依据"
go test -race ./...       # 验证并发审计的竞态安全
```

## 决策链路（gateway.Access）

```
请求(主体, 用途, 类别, 字段, 判定时刻, 策略版本)
  │
  1. 解析策略版本（空=当前版本；版本不存在 → policy_version_missing）
  2. 同意校验 consent.Evaluate
       consent_not_found / consent_expired / consent_withdrawn
       purpose_out_of_scope / category_not_granted
  3. 策略矩阵：用途 → 类别 （不通过 → policy_denies）
  4. 字段授权：显式请求字段必须是授权字段子集（越界 → field_unauthorized）
  5. 读取原始健康记录（仅在全部通过后触碰数据）
  6. 最小化 + 标识脱敏（失败 → mask_failure / field_missing，绝不回退原始数据）
  7. 写 decision 审计（标注策略版本与判定依据）
  8. 写 data_read 审计（实际返回字段 + 降级痕迹）
```

任何拒绝路径都**只写一条 decision 审计，不读取、不返回任何健康数据**。

## 典型用法

```go
reg := policy.NewRegistry()
_ = reg.Publish(&policy.Policy{ /* Version, PurposeGrants, Categories */ })

cs := consent.NewMemoryStore()
_ = cs.Save(&consent.Grant{ID: "g1", SubjectID: "alice",
    Categories: []policy.DataCategory{"labs"}, Purposes: []string{"care"},
    ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour),
    Status: consent.StatusActive})

ds := storage.NewStore()
ds.Seed(storage.Record{SubjectID: "alice", Category: "labs",
    Data: map[string]string{"glucose": "5.6"}})
aud := audit.NewStore()

gw := gateway.New(reg, cs, ds, aud)
resp, _ := gw.AccessOnBehalf(gateway.Request{
    Actor: "app", SubjectID: "alice", Purpose: "care", Category: "labs",
    Fields: []string{"glucose"},
})
// resp.Allowed / resp.Reason / resp.Detail / resp.Data / resp.AccessID

// 之后任意时刻按历史策略版本回放
rep, _ := gw.Replay(resp.AccessID, "auditor", time.Now())
// rep.Consistent == true 表示历史结论可复现
```

## 进一步阅读

设计细节、拒绝原因码、脱敏规则、版本回放语义见 [`doc/DESIGN.md`](doc/DESIGN.md)。
