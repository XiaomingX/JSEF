# JSEF Benchmark

> 用途：在 JSEF 现有 35+ 漏洞教学案例基础上，建立一套**验收 SAST 基础能力**与**对比多个大模型漏洞挖掘能力差异**的 benchmark。
> 验收维度：误报（FP）、漏报（FN）、平均耗时、超时样本、报告简洁度、能力完备程度（CWE 覆盖）。
> 设计依据见仓库根目录 `MY_PLAN.md`（Phase A2 统一提示词协议 / A3 区分度分级 L0–L5 / Phase C 验收基础设施）。

---

## 1. 为什么要做这个 Benchmark

SAST 的本质是"在不执行代码的前提下，从 source 到 sink 证明不可信数据可达危险操作"。JSEF 原有案例以教学对比为目的，区分度梯度不足、且缺乏机器可读标注，无法自动算 TP/FP/FN/TN。

本 benchmark 解决三件事：

1. **统一协议**：所有被测对象（SAST 工具 + 大模型）用同一提示词、对同批样本产出机器可读结果。
2. **区分度梯度**：样本按 L0–L5 分级，能拉开"入门级 SAST / 强 SAST / 不同档次 LLM"的差距。
3. **交叉对比**：用 scorecard 脚本产出工具 × 模型 × 样本的 Recall / Precision / Youden Score / 时延，识别谁漏报多、谁误报多、谁超时、谁报告简洁。

---

## 2. 目录结构

```
benchmark/
├── README.md                 # 本文件：运行与对比说明
├── prompts/
│   └── vuln_hunt.md          # 统一提示词模板（强制 SARIF 输出）
├── cases/                    # 样本库（源码级，可独立编译）
│   ├── vuln/                 # 不安全样本（按 CWE 分目录）
│   ├── sec/                  # 安全对照样本
│   └── vendor/               # 竞品对照集（OWASP Benchmark / Juliet 等抽象）
├── scripts/                  # scorecard 计算脚本（见 §5）
├── expectedresults.csv       # 全样本真/假标注（唯一事实源，Phase C1）
└── results/                  # 各被测对象产出（SARIF/JSON + 耗时），按对象分目录
    ├── codeql/
    ├── sonarqube/
    └── claude-<model>/
```

> 注：`expectedresults.csv` 已落地并持续维护，**当前共 259 个 checkpoint（含表头 260 行）**，覆盖 L0–L5 全梯度与 OWASP Top 10 2021 十类；`results/` 由各被测对象首次运行后填充。

---

## 3. 样本与区分度分级

样本按推理距离 + 语义依赖分为 L0–L5（详见 `MY_PLAN.md` A3）。其中 **L0 为能力基准（CAP-01/02），现已新增 18 个 L0 样本（9 类 × vuln+sec 配对），所有工具/模型都应命中**；余下样本覆盖 L1–L5，形成完整梯度：

- **L0 显式（能力基准）**：source 直接传入 sink，无中间变量，所有工具/模型都应命中（共 18 个 L0 vuln+sec 配对）。
- **L1 单跳**：1 个中间变量。
- **L2 多跳（无断点）**：≥2 中间变量/函数，弱工具在断点丢污点。
- **L3 间接/跨方法**：污点经 Map/字段/方法返回值，或跨方法。
- **L4 跨文件/框架语义/状态机**：跨编译单元、Spring 绑定语义、配置开关。
- **L5 gadget chain**：多个安全类组合成危险可达性（CC 链级别）。

> 历史说明：早期 `MY_PLAN.md` A3 与本文档旧版曾标注"当前 `expectedresults.csv` 中无样本标记为 L0"，该表述已于 Phase 1（L0 基线补全）落地后**更正**——详见 `MY_PLAN.md` Phase G 与 `plans/00-benchmark-gap-completion.md`。

每条样本在源码精确行标注 `// [CHECKPOINT id=... cwe=... level=... expect=VULN|SAFE]`，元数据同步写入 `expectedresults.csv`。

---

## 4. 如何运行被测对象

### 4.1 被测对象

- **SAST 工具**：CodeQL / SonarQube / Snyk 等，将其规则产出**人工转换为 SARIF**（或直接输出 SARIF），落到 `benchmark/results/<tool>/`。
- **大模型**：在 Claude Code 中切换模型（如 `claude-opus-4`、`claude-sonnet-4` 等），对同批样本使用**完全相同**的提示词 `benchmark/prompts/vuln_hunt.md`，产物落到 `benchmark/results/claude-<model>/`。

### 4.2 运行步骤

1. 启动 JSEF（如需带运行时上下文）：
   ```bash
   mvn clean package -DskipTests && java -jar target/*.jar
   ```
2. 选定被测对象，对 `benchmark/cases/`（及必要的 `src/.../vulnerability/`）跑一遍漏洞挖掘。
3. **强制**使用 `benchmark/prompts/vuln_hunt.md` 提示词，输出 SARIF（或退化为 `id → {hit, file, line, message}` JSON 列表）。
4. 记录每个样本 `start_ts` / `end_ts`，超 120s 记为超时样本。
5. 将产物写入 `benchmark/results/<object>/<case>.sarif`（或 `.json`）。

> 关键：大模型对比时，**只切换模型、不改提示词、不换样本**，否则结果不可比。

---

## 5. 如何产出结果 + 跑 Scorecard

1. 确保 `benchmark/expectedresults.csv` 已存在（每条样本 `id, cwe, level, type(vuln/safe), file, line, source, sink, category`）。
2. 运行 `benchmark/scripts/` 下的 scorecard 脚本（Python），输入为某对象的 SARIF/JSON 结果：
   ```bash
   python benchmark/scripts/scorecard.py \
     --expected benchmark/expectedresults.csv \
     --results  benchmark/results/claude-<model>/ \
     --out      benchmark/results/claude-<model>/scorecard.json
   ```
3. 脚本输出：
   - TP / FN / FP / TN → **Recall / Precision / Youden Score = TPR − FPR**（OWASP 口径，0–100）。
   - 综合指标 **F1 = 2·P·R/(P+R)** 与 **MCC（Matthews 相关系数）**：正负样本不均衡时 MCC 比 Youden 更稳健，三指标并列输出。
   - **真实时延**：逐样本 `elapsed_ms` 汇总为 `avg / p50 / p95 / max` 与 **超时率 `timeout_rate`**（阈值取 `--timeout-ms`，默认 120000ms）。
   - **定位精度**：`exact_hit_rate`（file:line 精确命中率）与 `near_hit_rate`（容差内命中率），容差由 `--line-tolerance` 控制（默认 0 严格；设为 2 表示 ±2 行内算 near hit）。
   - 报告简洁度（有效告警 / 输出量）、能力完备度（命中 CWE 覆盖数）。
   - 按 CWE 与 level 分组的"能力档位"数据，用于雷达图。

### 5.1 scorecard 关键参数

| 参数 | 说明 |
|------|------|
| `--expected <csv>` | 事实源 `expectedresults.csv`（必填）。 |
| `--result <file/dir>` | 单对象结果（SARIF 或 `id→{hit,file,line,...}` JSON）。 |
| `--results-dir <dir>` | 多对象根目录，遍历 `<dir>/<object>/result.json`（或首个 `*.sarif`），产出**交叉矩阵 `cross_matrix.json`**（object × metric + object × CWE 热力），供 `generate_report.py` 消费。 |
| `--line-tolerance <k>` | 定位精度容差（行）。`exact_hit_rate` 要求行精确，`near_hit_rate` 放宽到 ±k 行。默认 0。 |
| `--timeout-ms <ms>` | 单次样本超时阈值，用于超时统计（默认 120000）。 |
| `--name <object>` | 被测对象名（单对象模式写 `scorecard.json` 时用）。 |
| `--out <path>` | 输出 JSON 路径。 |

> scorecard 已升级为行业标准口径（时延/定位/F1/MCC/交叉矩阵），对应 `MY_PLAN.md` Phase G（G1）与 `plans/00-benchmark-gap-completion.md` Phase 6。

### 5.2 双源校验（门禁自测）

新增/修改任何样本前与收尾前，**必须**运行双源校验脚本，确认 CSV 与源码 `// [CHECKPOINT]` 注解双向一致：

```bash
python3 benchmark/scripts/validate_checkpoints.py \
  --expected benchmark/expectedresults.csv \
  --cases-dir benchmark/cases \
  --src-dir src/main/java/com/freedom/securitysamples/vulnerability
```

校验项与退出码：

| 校验项 | 含义 | 触发后果 |
|--------|------|----------|
| 孤儿 CSV 行 | CSV 有 id 但源码无 `// [CHECKPOINT]` 注解 | 退出码 1 |
| 孤儿源码注解 | 源码有注解但 CSV 无对应行 | 退出码 1 |
| 重复 id | CSV 内或源码内同一 id 出现多次 | 退出码 1 |
| 行号漂移 | CSV `line` 列 ≠ 注解实际行号（`grep -n`） | 退出码 1 |
| CSV `line` 列无效 | `line` 无法解析为整数 | 退出码 1 |

- **退出码 0 = 通过**（无孤儿/重复/漂移）；**退出码 1 = 存在问题**；找不到 CSV 或表头缺列返回 2。
- 该脚本为纯标准库实现（无第三方依赖），不依赖项目 Maven 构建。
- 此校验是 AGENTS.md / CLAUDE.md 门禁的硬性自测项，未通过则样本任务视为未完成。

> 详见脚本头部 docstring：`benchmark/scripts/validate_checkpoints.py`。

---

## 6. 交叉对比

对每个被测对象各产出一份 scorecard，横向比对：

| 维度 | 关注点 |
|------|--------|
| Recall | 谁漏报多（FN 高，尤其 L3–L5） |
| Precision | 谁误报多（FP 高，Safe 混淆样本） |
| Youden Score | 综合档位（0–100，越高越好） |
| 时延 / 超时率 | 谁慢、谁超时 |
| 报告简洁度 | 谁啰嗦、谁精准到 file:line |
| CWE 覆盖 | 谁能力完备度高 |

由此识别"入门级 SAST / 强 SAST / 不同档次 LLM"的差异，定位各对象的能力断点。

---

## 7. 安全底线

所有样本 Payload 仅限 `localhost` 演示（遵循仓库 `agent.md` 安全底线）。本 benchmark 只做**静态**分析与对比，不执行任何攻击代码。

---

## 8. 行业标准报告（端到端 harness）

`benchmark/run_benchmark.sh` 封装端到端流程，依次调用 scorecard 与报告生成器，产出可横向对比、符合行业阅读习惯的报告：

```bash
./benchmark/run_benchmark.sh <results-root> <expected-csv> <timeout-ms>
# 例：
./benchmark/run_benchmark.sh benchmark/results benchmark/expectedresults.csv 120000
```

**参数**
- `results-root`：结果根目录；其下每个子目录是一个被测对象（含 `result.json` 或 `*.sarif`）。
- `expected-csv`：事实源 `expectedresults.csv` 路径。
- `timeout-ms`：单次样本超时阈值（ms，默认 120000），用于超时统计。

**端到端产出**（`results-root/` 下）
| 产出 | 说明 |
|------|------|
| `cross_matrix.json` | 多对象交叉矩阵：object × metric + object × CWE 热力（由 scorecard `--results-dir` 聚合）。 |
| `report.md` | 人类可读总表 + 逐 OWASP 类章节 + L0–L5 档位表 + OWASP Benchmark 式 Youden 排名。 |
| `report.json` | 机器可读报告（总表 / 排名 / 逐 OWASP 类 / 逐 Level 聚合），供 CI 或仪表盘消费。 |
| `radar_data.json` / `ranking.png`（可选） | 若环境有 `matplotlib` 则画 Youden 排名图，否则仅出 `radar_data.json` 原始数据。 |

**报告内容结构**
1. **总表**：按 Youden 降序，列含 Recall / Precision / F1 / MCC / Youden / 超时率 / 定位精度(exact_hit_rate) / 能力完备度。
2. **逐 OWASP Top 10 类章节**：每类（A01–A10 + Other）含样本类别、各对象 Recall/Precision/F1/Youden/混淆矩阵。
3. **按 Level 能力档位表（L0–L5）**：每档位各对象的 Youden / F1 / Recall / Precision。
4. **OWASP Benchmark 式 Youden 排名**：对象按 Youden（0–100）降序并给档位评价（优秀/良好/中等/偏弱/弱）。

**OWASP Top 10 映射口径**
报告按 `expectedresults.csv` 的 `category` 列映射到 OWASP Top 10 2021（映射表硬编码于 `benchmark/reports/generate_report.py` 的 `OWASP_MAP`）：
- A01 Broken Access Control：`idor*` / `broken-access-control` / `authorization-bypass` / `auth-bypass` / `business-logic`(部分) 等。
- A02 Cryptographic Failures：`crypto*` / `weak-*` / `hardcoded-*` / `reused-iv` / `default-credentials` 等。
- A03 Injection：`sql-*` / `command-*` / `xss-*` / `spel-*` / `*-injection` / `xxe` / `xpath-*` / `ldap-*` / `nosql-*` / `template-*` / `header-injection` / `log-injection` / `jsonp-*` / `jwt-*` 等。
- A04 Insecure Design：`business-logic` / `mass-assignment` / `race-condition` / `workflow*` 等。
- A05 Security Misconfiguration：`cors*` / `security-header*` / `missing-*` / `debug-*` / `error-info-leak` / `insecure-cookie` / `config-gated-sink` / `clickjacking` 等。
- A06 Vulnerable & Outdated Components：`vulnerable-components`。
- A07 Identification & Authentication Failures：`weak-password` / `sensitive-data-*` / `jwt-auth-bypass`(部分) / `auth-bypass`(部分) 等。
- A08 Software & Data Integrity Failures：`insecure-integrity`。
- A09 Security Logging & Monitoring Failures：`security-logging`。
- A10 Server-Side Request Forgery：`ssrf`。
- 未在表中命中的未知 category → `Other`（另有前缀模糊匹配兜底）。

> 报告生成器与 harness 对应 `MY_PLAN.md` Phase G（G7）与 `plans/00-benchmark-gap-completion.md` Phase 7。
> **公平性约束**（harness 已明文化）：同提示词、同样本、只换被测对象（SAST 工具 / 不同 LLM），不改提示词、不换样本、不改超时阈值，否则结果不可比。

---

## 9. 新增样本 Checklist（贡献者必读）

新增或修改任何漏洞样本（无论 `src/main/.../vuln` 还是 `benchmark/cases/`）必须完成以下步骤，缺一不可：

1. **写样本**：漏洞代码放 `vuln/`（或 `src/main` 对应目录），配套安全对照放 `sec/`。语义正确、可读，仅 localhost 演示语义。
2. **加 checkpoint**：在漏洞精确行上方加机器可读注解：
   ```java
   // [CHECKPOINT id=JSEF-<类别>-<序号> cwe=<CWE编号> level=<L1-L5> source=<不可信源> sink=<危险终点> expect=VULN]
   ```
   安全对照（混淆样本）加 `expect=SAFE`（用于算 TN/FP）。
3. **同步 CSV**：把该 checkpoint 追加到 `benchmark/expectedresults.csv`（表头 `id,cwe,level,type,file,line,source,sink,category`），`type` 为 `vuln`/`safe`，`line` 为注解实际行号。
4. **自测一致性**：确认 CSV 与源码两源 id 完全一致（无孤儿行、无重复 id）：
   ```bash
   python3 benchmark/scripts/scorecard.py --expected benchmark/expectedresults.csv --result <你的结果> --name self-check
   ```
5. **提交**：遵循仓库 `CLAUDE.md` / `AGENTS.md` 的 checkpoint 门禁要求。

> id 全局唯一：`benchmark/cases` 与 `src/main` 下的同类样本可用不同序号（如 cases 用 `001`、src 用 `002`），但每个 `id` 必须在 CSV 与源码中同时存在且一一对应。
