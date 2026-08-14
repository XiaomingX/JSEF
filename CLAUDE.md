# CLAUDE.md — JSEF 贡献者规范（面向 Claude Code）

## 项目定位

**JSEF = Spring Boot 3.x Java 安全教学框架 + 漏洞挖掘 benchmark。**

既有 35+ 漏洞教学案例（`src/main/...`），又提供一套可验收 SAST 基础能力与对比多模型漏洞挖掘能力的 benchmark（`benchmark/`）。

## 核心贡献规则（最重要）

新增或修改任何漏洞样本（无论位于 `src/main/java/.../vulnerability/.../vuln` 还是 `benchmark/cases/`）时，**必须**遵守以下两条，缺一不可：

1. **加机器可读 checkpoint 注解**：在漏洞的精确行（污点到达 sink 的那一行）上方加一行注释：

   ```
   // [CHECKPOINT id=JSEF-XXX-001 cwe=<CWE编号> level=<L1-L5> source=<不可信源> sink=<危险终点> expect=VULN|SAFE]
   ```

   真实示例（来自 `benchmark/cases/vuln/TaintSingleHop.java:22`）：

   ```java
   // [CHECKPOINT id=JSEF-TP-001 cwe=78 level=L1 source=userInput sink=Runtime.getRuntime().exec expect=VULN]
   Process p = Runtime.getRuntime().exec(userInput);
   ```

   - `expect=VULN` → 应报（计入 TP/FN）；`expect=SAFE` → 不应报（计入 TN/FP）。
   - `id` 建议统一前缀 `JSEF-<类别>-<序号>`，全局唯一（如 `JSEF-SQLI-001`、`JSEF-TP-005S`）。给出示例但不强制具体编号。

2. **同步追加到 `benchmark/expectedresults.csv`**：将 checkpoint 的元数据作为新行追加，保持两源一致。

   CSV 表头（已是事实源，不要改列顺序）：

   ```
   id,cwe,level,type,file,line,source,sink,category
   ```

   - `type` 为 `vuln`（对应 `expect=VULN`）或 `safe`（对应 `expect=SAFE`）。
   - `line` 为 checkpoint 注解所在源码行号（污点到达 sink 的精确行）。
   - 示例行（对应上面的 checkpoint）：

     ```
     JSEF-TP-001,78,L1,vuln,benchmark/cases/vuln/TaintSingleHop.java,22,userInput,Runtime.getRuntime().exec,command-injection
     ```

> 缺 checkpoint 注解，或 CSV 未同步追加，即视为该样本未提交完成。

## 安全底线（引自 agent.md）

- 所有 Payload 仅限 `localhost` 演示语义，**不写真实攻击利用脚本**。
- 不生成任何用于恶意攻击真实目标的脚本或工具。
- 解释漏洞原理时，必须紧跟修复方案（对照 `sec` 安全代码）。

## 标注与包结构约定（引自 skill.md）

- 保留现有行内标记 `// [VULN]`（如 `// [VULN] 漏洞点：直接使用了用户输入的ID`）。`[CHECKPOINT]` 与之互补：`[VULN]` 偏教学说明，`[CHECKPOINT]` 偏机器可读验收。
- **包名隔离**：不安全代码放 `vuln` 子包，修复后的安全代码放 `sec` 子包；URL 形如 `/api/v1/{type}/unsafe/{scenario}` 与 `/api/v1/{type}/safe/{scenario}`。

## 区分度分级 L1–L5（引自 MY_PLAN A3）

- **L1 单跳**：1 个中间变量，source→sink 直连。
- **L2 多跳（无断点）**：≥2 中间变量/函数，弱工具在断点丢污点。
- **L3 间接/跨方法**：污点经 Map/字段/方法返回值，或跨方法。
- **L4 跨文件/框架语义/状态机**：跨编译单元、Spring 绑定语义、或依赖配置开关。
- **L5 gadget chain**：多个单独安全的类组合成危险可达性（CC 链级别）。

> L0（显式直连）为理论基线，实际新增样本从 L1 起步。

## 本地自测新增样本

跑 scorecard 自测，验证 checkpoint 与 CSV 是否被正确计分：

```bash
python benchmark/scripts/scorecard.py \
  --expected benchmark/expectedresults.csv \
  --result <你的结果文件或目录>
```

跑**双源校验（门禁必跑项）**，确认 CSV 与源码 `// [CHECKPOINT]` 注解一致、无孤儿/重复/行号漂移，要求退出码为 0：

```bash
python3 benchmark/scripts/validate_checkpoints.py \
  --expected benchmark/expectedresults.csv \
  --cases-dir benchmark/cases \
  --src-dir src/main/java/com/freedom/securitysamples/vulnerability
```

> 退出码非 0 即门禁未过，新增/修改样本任务不得视为完成（与 AGENTS.md 门禁一致）。

## 编译与可读性要求

- **不要求**编译 `benchmark/cases/` 下的样本——这些文件用于静态分析 / LLM 阅读。
- 但样本**语义必须正确、可读**：污点流（source→sink）要清晰，注释要解释"为什么有漏洞"与数据流动路径。

## 一句话自检清单

- [ ] 漏洞精确行上方有 `// [CHECKPOINT ...]` 注解
- [ ] 该行已追加到 `benchmark/expectedresults.csv`（9 列齐全，type 与 expect 一致）
- [ ] Payload 仅 localhost 语义，无真实利用脚本
- [ ] `vuln`/`sec` 包分离与 `// [VULN]` 约定保留
- [ ] 跑了 scorecard 自测
