# AGENTS.md — JSEF Agent 执行规范（面向通用自动化 Agent）

## 项目定位

**JSEF = Spring Boot 3.x Java 安全教学框架 + 漏洞挖掘 benchmark。** 既有 35+ 漏洞教学案例，又提供验收 SAST 能力与对比多模型漏洞挖掘的 benchmark。本文件面向 Codex / 其他 LLM Agent 等自动化执行者，规定"新增或修改漏洞样本"任务的硬性门禁。

## 核心门禁：checkpoint 是任务完成的硬条件

对任何新增/修改漏洞样本的任务，**checkpoint 是硬性门禁**——以下任一项缺失，任务即判定为**未完成**：

1. 未在漏洞精确行（污点到达 sink 的源码行）上方加 `// [CHECKPOINT ...]` 注解；
2. 未将同一 checkpoint 的元数据同步追加到 `benchmark/expectedresults.csv`；
3. 两源不一致（如 CSV 行号与源码注解行号不符、`type` 与 `expect` 矛盾）。

> 缺 checkpoint 或 CSV 不同步 = 任务未完成。务必在收尾前核对两源。

### checkpoint 注解格式

```
// [CHECKPOINT id=JSEF-XXX-001 cwe=<CWE编号> level=<L1-L5> source=<不可信源> sink=<危险终点> expect=VULN|SAFE]
```

真实示例（来自 `benchmark/cases/vuln/TaintSingleHop.java:22`）：

```java
// [CHECKPOINT id=JSEF-TP-001 cwe=78 level=L1 source=userInput sink=Runtime.getRuntime().exec expect=VULN]
Process p = Runtime.getRuntime().exec(userInput);
```

- `expect=VULN` → 应报（`type=vuln`）；`expect=SAFE` → 不应报（`type=safe`）。
- `id` 建议前缀 `JSEF-<类别>-<序号>`，全局唯一（如 `JSEF-TP-005S`）。给出示例但不强制具体编号。

#### 可选 `trace=` 字段（路径证据链）

借鉴 VulnGym 的 `entry_point → critical_operation → trace` 多节点理念，注解支持可选 `trace=` 字段，记录入口到危险操作之间的中间推理节点：

```
// [CHECKPOINT id=JSEF-XXX cwe=<CWE> level=L4 source=... sink=... expect=VULN trace=FileA.java:lineB,FileC.java:lineD]
```

- **格式**：逗号分隔的 `file:line` 节点列表（相对仓库根路径），如 `trace=OrderController.java:42,TenantService.java:18`。
- **适用场景**：**仅 L3+ 且涉及跨节点（跨方法/跨文件/业务链）的样本**使用；单点直连样本（L0–L2）不加，保持单点命中评测语义。
- **作用**：支持"路径正确性"评测；CSV 第 10 列 `trace` 同步写入相同节点串，scorecard `--check-trace` 据此计算 `trace_recall`/`trace_precision`。
- **约束**：`trace=` 若使用，每个 `file:line` 都必须指向真实存在的源码行——`validate_checkpoints.py` 会解析并告警（见下方步骤清单与「完成判定」）。

### CSV 同步格式

`benchmark/expectedresults.csv` 表头（事实源，列顺序勿改）：

```
id,cwe,level,type,file,line,source,sink,category
```

对应示例行：

```
JSEF-TP-001,78,L1,vuln,benchmark/cases/vuln/TaintSingleHop.java,22,userInput,Runtime.getRuntime().exec,command-injection
```

- `line` = checkpoint 注解所在源码行号（污点到达 sink 的精确行）。
- `type` 与 `expect` 严格对应：`vuln`↔`VULN`，`safe`↔`SAFE`。

## Agent 最小可执行步骤清单

1. **写样本**：在 `src/main/.../vuln` 或 `benchmark/cases/vuln` 落地漏洞代码，污染数据流（source→sink）清晰可读。
2. **加 checkpoint**：在污点到达 sink 的精确行上方加 `// [CHECKPOINT ...]`。
3. **补 CSV**：把同一 `id` 的 9 列元数据追加到 `benchmark/expectedresults.csv`，`type`/`expect` 一致、`line` 为真实行号。
4. **（可选）安全对照**：配套 `sec` 安全样本并加 `expect=SAFE` 的 checkpoint + CSV 行，用于计算 FP/TN。
5. **自测**：运行 `python benchmark/scripts/scorecard.py --expected benchmark/expectedresults.csv --result <你的结果>` 验证两源可被同一 id 关联。
6. **核对门禁（必跑双源校验）**：在新增/修改样本前与收尾前，**必须**运行双源校验脚本，要求退出码为 0：
   ```bash
   python3 benchmark/scripts/validate_checkpoints.py \
     --expected benchmark/expectedresults.csv \
     --cases-dir benchmark/cases \
     --src-dir src/main/java/com/freedom/securitysamples/vulnerability
   ```
   该脚本校验 CSV 与源码 `// [CHECKPOINT]` 注解之间的孤儿行、孤儿注解、重复 id、行号漂移（详见 `benchmark/README.md` §5.x）。**退出码非 0 即门禁未过，任务不得视为完成。**
   - 若样本使用了 `trace=` 字段，脚本会额外做"trace 节点有效性"检查（格式/文件存在性/行号越界），**仅告警不阻断**；但节点必须真实存在，否则告警提示需修正路径后再交付。

## 安全底线（引自 agent.md）

- 所有 Payload 仅 localhost 演示语义，**不写真实攻击利用脚本**，不生成针对真实目标的工具。
- 解释漏洞须紧跟修复方案（对照 `sec` 代码）。

## 标注与包结构约定（引自 skill.md）

- 保留 `// [VULN]` 行内教学注释；`[CHECKPOINT]` 是其机器可读补充，二者共存不冲突。
- 漏洞代码放 `vuln` 包，修复代码放 `sec` 包；URL 形如 `/api/v1/{type}/unsafe/{scenario}` 与 `/api/v1/{type}/safe/{scenario}`。

## 区分度分级 L1–L5（引自 MY_PLAN A3）

- **L1 单跳**：1 中间变量，source→sink 直连。
- **L2 多跳（无断点）**：≥2 中间变量/函数。
- **L3 间接/跨方法**：经 Map/字段/方法返回值，或跨方法。
- **L4 跨文件/框架语义/状态机**：跨编译单元、Spring 绑定语义、配置开关。
- **L5 gadget chain**：多安全类组合成危险可达性（CC 链级别）。

## 编译与可读性要求

- `benchmark/cases/` 样本**不要求编译**（供静态分析 / LLM 阅读），但语义须正确可读，污点流清晰。
- 自测用 `benchmark/scripts/scorecard.py`，不依赖项目 Maven 构建。

## 完成判定

任务完成的唯一标准：**源码 `// [CHECKPOINT]` 与 `expectedresults.csv` 两源一致、皆含新样本 id**，**且 `benchmark/scripts/validate_checkpoints.py` 退出码为 0**，且未触发安全底线。否则视为未完成，需补齐后再交付。**若使用了 `trace=` 字段，其每个 `file:line` 必须指向真实存在的源码行（validate 仅告警但其指向无效即需修正），CSV 第 10 列 `trace` 与注解需同步。**
