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

> 注：`expectedresults.csv` 与 `results/` 在样本落地（MY_PLAN Phase B）与首次运行后生成；目前目录已就位但内容待填充。

---

## 3. 样本与区分度分级

样本按推理距离 + 语义依赖分为 L0–L5（详见 `MY_PLAN.md` A3）。其中 **L0 仅作能力基准参考（CAP-01/02），当前 `expectedresults.csv` 中无样本标记为 L0，实际样本均为 L1–L5**：

- **L0 显式（能力基准）**：source 直接传入 sink，所有工具/模型都应命中。
- **L1 单跳**：1 个中间变量。
- **L2 多跳（无断点）**：≥2 中间变量/函数，弱工具在断点丢污点。
- **L3 间接/跨方法**：污点经 Map/字段/方法返回值，或跨方法。
- **L4 跨文件/框架语义/状态机**：跨编译单元、Spring 绑定语义、配置开关。
- **L5 gadget chain**：多个安全类组合成危险可达性（CC 链级别）。

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
   - 平均耗时、超时样本数、超时率。
   - 报告简洁度（有效告警 / 输出量）、能力完备度（命中 CWE 覆盖数）。
   - 按 CWE 与 level 分组的"能力档位"数据，用于雷达图。

> scorecard 脚本骨架对应 `MY_PLAN.md` Phase C3；落地后补充到 `benchmark/scripts/`。

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

## 8. 新增样本 Checklist（贡献者必读）

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
