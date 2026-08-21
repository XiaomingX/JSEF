# JSEF × DeepSwe 借鉴：评测机制增强 + 复杂漏洞发现深度

> 目标：借鉴 DeepSwe（SWE-bench 风格，113 个长程工程任务，测"agent 改真实仓库+跑测试验证"）的**可借鉴点**，补充到 JSEF（Java 漏洞挖掘 benchmark）。两个方向：① 补评测机制（trials 稳定性 + 成本/步数维度，纯评测层）；② 复杂漏洞发现深度（补充更难样本）。全程遵循 AGENTS.md 双源门禁，**不改 scorecard.py**。

---

## 0. DeepSwe 评估机制（已核实官网 + 任务详情页）
- 定位："Measuring frontier coding agents on original, long-horizon engineering tasks"。
- 四维 advance：无污染（任务从零写）、高多样性（91 仓库/5 语言）、真实复杂度（5.5x 代码）、可靠验证（verifier 手写测**行为**非实现）。
- 评估：Pass@1；每模型跑 **N 次 trials 全过才算通过**；榜单展示 Avg cost / Out tok / Steps。
- 任务详情页：Instruction、base commit、Verifier(+318 行)、Solution/gold patch(+472/-407)、task.toml、Trials。

## 0.2 借鉴决策
| DeepSwe 特性 | 对 JSEF 价值 | 决策 |
|---|---|---|
| trials 稳定性（N 次全过） | JSEF 单次算分无稳定性 | ✅ 借鉴（方向①） |
| agent 步数/成本维度 | JSEF 有 elapsed_ms 无 cost/steps | ✅ 借鉴（方向①） |
| verifier 测行为非实现 | 已有 --check-trace/--check-plan | ⚠️ 部分（已有） |
| 改真实仓库+跑 Maven 测试 | JSEF SNIPPET 级不编译（AGENTS.md:110） | ❌ 不借鉴（大改动） |
| 多语言真实仓库长程修改 | 与静态读码报漏洞定位不同 | ❌ 不借鉴 |

---

## 1. 方向①：trials 稳定性评测机制

### 目录约定
`benchmark/results/<object>/trial_<i>/result.json`（零填充排序稳定）。对象含 ≥1 个 `trial_<i>/` → trials 模式；否则单次模式。

### 聚合算法
- per-trial：复用 scorecard `score_object` → 每 sample `outcome ∈ {TP,FN,FP,TN}`。
- per-sample：`判对=(vuln and outcome==TP) or (safe and outcome==TN)`；`pass_all`=N 次全对 → **sample_pass@1**（DeepSwe 全过语义）；`pass_rate`=判对数/N。
- 对象级：`object_pass@majority`（≥⌈N/2⌉ 过）；稳定性 `acc_mean/acc_std/spread=best-worst`。

### 文件
| 文件 | 职责 | 类型 |
|---|---|---|
| `benchmark/scripts/trials_aggregate.py` | 核心聚合（detect_trials/aggregate_trials）+ CLI | 新增 |
| `compare_models.py` | 集成 trials 聚合，排行表/图表展示 Pass@1/std/spread/成本/步数 | 修改 |
| `run_llm_benchmark.py` | `--trials N` 循环写 trial_i/result.json + meta.json | 修改 |

### CLI
```
compare_models.py --results-dir ... [--min-trials 2] [--majority-k 0]
benchmark/scripts/trials_aggregate.py --object <dir> --out trials_matrix.json
run_llm_benchmark.py --model glm-5.3 --trials 5 --name my-model
```

---

## 2. 方向②：复杂漏洞发现深度（6 样本）

| id | CWE | L | category | 语义 |
|---|---|---|---|---|
| JSEF-MULTIGATE-001 / 001S | 917 | L5 | multi-state-gate | SpEL sink 需 config.enabled && version<2.0 && role==ADMIN 多条件联合可达（trace 跨配置/版本/角色） |
| JSEF-JWTCHAIN-001 / 001S | 347 | L5 | jwt-chain | 弱算法+可控密钥+过期缺陷+权限篡改 4 环节串联绕过（trace 跨 4 节点） |
| JSEF-ASYNCCHAIN-001 / 001S | 89 | L4 | async-taint-chain | CompletableFuture supplyAsync→thenApply→thenCompose→thenApply 多级异步传播后进 SQL sink |

---

## 3. 验证
- 方向①：mock trials（example_result 造 modelA/trial_1..4 其中 trial_4 反相）→ 断言 Pass@1/spread>0、modelC 单次回归一致。
- 方向②：validate_checkpoints.py 退出码 0；新样本 id 唯一、trace 节点真实、type/expect 一致。
- 门禁：scorecard.py 零改动；现有 CSV 仅追加。

## 4. 反模式防护
- 勿把 DeepSwe"改真实仓库+跑 Maven 测试"强加给 JSEF（样本仍 SNIPPET 级不编译）。
- 勿改 scorecard.py（门禁依赖）；trials 聚合只读 score_object/_find_result_file。
- 勿发明 API：新样本 sink 用语义桩 + `// 语义等价:`；异步用标准 CompletableFuture。
- 勿重复已有样本：async-taint(单层) vs async-chain(多级)；config-gated(单开关) vs multi-state-gate(多条件)；JWT 单点 vs jwt-chain(多环节)。
