# 计划 05：基于 Struts2 漏洞第一性原理的「OGNL 表达式机制」原子级样本集

> 目标：从近期 Apache Struts2 0day/1day 中抽象出**与 Struts2 无关**的原子原理范式，
> 构造符合 MECE 原则的复杂漏洞样本（vuln + sec 对照），用于评估大模型 / harness
> 对「同类原理」漏洞的检测能力。样本用 Java 标准库语义**自包含**复现，
> **不出现 Struts2 / OGNL / XWork 等具体框架类名**。
>
> **去重约束（重要）**：仓库已有大量「单层、直输即 eval」的表达式求值样本
> （`JSEF-OGNL-001/002`、`JSEF-SPEL-*`、`JSEF-EL-001`、`JSEF-GROOVY-*`、`JSEF-BEANSHELL-*`、
> `ConfusionSpelConstantSink`、`SpelFrameworkSemantics`、`L0SpelDirect`）。本计划**不**重复
> 这些单层场景，只覆盖 Struts2/OGNL 漏洞中「现有样本尚未建模」的 3 个独特原子维度，
> 新名字空间 `JSEF-STR-`。

---

## 0. 背景：Struts2 漏洞的第一性原理抽象

### 0.1 近期 Struts2 0day/1day 事实（公开来源，仅作抽象依据）

| 真实漏洞 | 机制（已公开确认） |
|---|---|
| OGNL 注入系列（S2-012/016/045/061 等） | 用户输入（参数 / Content-Type 头 / action 名 / 错误信息）被当作 OGNL 表达式求值 → RCE。 |
| S2-045 (CVE-2017-5638) | HTTP `Content-Type` 头（协议层字段）数据流入 OGNL 求值引擎 → RCE。核心是「协议/元数据层数据被当表达式」。 |
| S2-061 等沙箱绕过 | Struts2 对 OGNL 加排除列表（黑名单类如 `java.lang.Runtime`），攻击者用 `(expr1).(expr2)` 串联、上下文切换（`#context`/`#_memberAccess` 改访问权限）、反射变形绕过排除列表。核心是「表达式内运行时沙箱/排除列表被绕过」。 |
| OGNL 双层求值 | OGNL 的 `%{...}` / `${...}` 嵌套：一次求值的结果字符串若仍含表达式语法，会被二次解析执行（double evaluation）。这是 OGNL 最独特、最难静态检测的特性。 |

### 0.2 与现有样本的边界（MECE 保证）

- `JSEF-OGNL-001/002`、`JSEF-SPEL-*` 等均是**单层、直输即 eval**（`parseExpression(userInput)`）。本计划**不**写同类单层场景。
- `JSEF-EL-001` 是单层 EL 求值。**不**重复。
- `DBG-3` 是**类名字符串级**名单绕过（字符串匹配）。`STR-3` 是**表达式运行时上下文权限提升**（表达式内改 `#_memberAccess` 访问权限），二者维度不同。
- `SBM-3` 是高权限端点暴露（业务动作）。`STR-2` 是**协议层字段被当表达式**（非业务参数通道），维度不同。

### 0.3 跨框架的不变原子范式（去 Struts2 化）

Struts2/OGNL 漏洞中现有样本**未覆盖**的底层危险组合（3 个维度，互不重叠）：

- **STR-1（Double Evaluation / 双层求值）** = 表达式求值的结果字符串仍含表达式语法，被再次解析执行。任何「求值结果可再次进入同一求值器」的表达式引擎都有同类风险（二次模板渲染、嵌套占位符解析）。
- **STR-2（Protocol/Metadata-layer Injection）** = 非业务参数的协议/元数据层数据（HTTP 头、状态码、错误信息、路径段）流入表达式求值引擎。任何「协议解析层与表达式引擎耦合」的系统都有同类风险。
- **STR-3（Eval Exclusion-list Bypass by Context Switch）** = 表达式引擎的排除列表（黑名单类/方法）被「表达式内上下文切换 + 串联子表达式」绕过，从而恢复被禁的运行时调用能力。任何「带沙箱的表达式引擎」都有同类风险。

---

## 1. 样本设计规范（遵守仓库门禁，见 AGENTS.md）

每个 vuln 样本：
- 路径：`benchmark/cases/vuln/str/STR{i}_{Scenario}.java`，包 `com.jsef.benchmark.vuln.str`
- 污点流 source→sink 清晰可读，保留 `// [VULN]` 行内注释
- sink 行上方加 `// [CHECKPOINT id=JSEF-STR-xxx cwe=917 level=Lx source=<源> sink=<终点> expect=VULN]`（L3+ 带 trace=，节点真实存在）
- sec 对照：`benchmark/cases/sec/str/STR{i}_{Scenario}_Safe.java`，`expect=SAFE` + CSV 行

CSV 追加到 `benchmark/expectedresults.csv`（列序 `id,cwe,level,type,file,line,source,sink,category,trace`）。

**门禁硬条件**：收尾 `validate_checkpoints.py` 退出码 0：
```bash
python3 benchmark/scripts/validate_checkpoints.py \
  --expected benchmark/expectedresults.csv \
  --cases-dir benchmark/cases \
  --src-dir src/main/java/com/freedom/securitysamples/vulnerability
```

**安全底线**：仅 localhost 演示语义；不写真实利用脚本、不连真实远端、不提供针对真实目标的 gadget。解释即附修复（sec 文件）。

---

## 2. 样本清单（3 维度 × 分级，建议 9 vuln + 9 sec）

### 维度 STR-1 Double Evaluation（CWE-917，对应 OGNL 双层求值）
- `JSEF-STR-101` L2：模板/表达式求值器对 `expr` 求值后，把结果再次 `evaluate(result)`（模拟 `%{...}` 嵌套）。危险表达式在第二次求值触发。
- `JSEF-STR-102` L4（跨文件/跨函数）：第一次求值在文件 A，结果字符串流入文件 C 的二次求值器执行（仿 longtask 跨文件）。带 trace。
- `JSEF-STR-101S/102S` sec：禁用二次求值（结果只当数据，不回灌求值器），或单层求值且输入白名单。

### 维度 STR-2 Protocol/Metadata-layer Injection（CWE-917，对应 S2-045 Content-Type）
- `JSEF-STR-201` L3：协议层字段（如 HTTP `Content-Type` 头 / 响应错误串）被直接送表达式引擎求值。带 trace（头→求值）。
- `JSEF-STR-202` L4：路径段 / action 名（非业务参数）经路由解析后流入 OGNL 风格求值。带 trace（跨方法）。
- `JSEF-STR-201S/202S` sec：协议层字段只当元数据，绝不进入表达式引擎；若需解析则严格白名单。

### 维度 STR-3 Eval Exclusion-list Bypass by Context Switch（CWE-917，对应 S2-061 沙箱绕过）
- `JSEF-STR-301` L3：表达式引擎有排除列表（禁止 `Runtime` 类），攻击者用 `(expr1).(expr2)` 串联 + 上下文切换（模拟 `#_memberAccess` 改访问权限）恢复调用能力，最终 `Method.invoke(Runtime.exec)`。带 trace。
- `JSEF-STR-302` L4：排除列表匹配的「精确方法名」，攻击者用表达式内反射（`getClass().getMethod(...)`）变形绕过，调用被禁方法。带 trace。
- `JSEF-STR-301S/302S` sec：上下文切换语句被禁用（求值前剥离 `#context`/`#_memberAccess` 等特殊引用），排除列表用 `Method` 对象精确匹配而非字符串。

---

## 3. 实施步骤（按 phase 推进，每 phase 后门禁校验）

### Phase A — STR-1 + STR-2（双层求值 + 协议层注入）
1. 写 `STR1_DoubleEvaluation.java`、`STR2_ProtocolLayerInjection.java` 及 `_Safe.java`（含 L4 跨文件/跨方法）。
2. 加 CHECKPOINT（精确 sink 行，L3/L4 带 trace）。
3. 追加 CSV 行，跑 `validate_checkpoints.py` 退出码 0。

### Phase B — STR-3（表达式排除列表绕过）
1. 写 `STR3_ExclusionListBypass.java` 及 `_Safe.java`。
2. 追加 CSV 行，跑 validate。

### Phase C — 难度收口
1. 全部追加后跑最终 `validate_checkpoints.py`（退出码 0）。
2. `scorecard.py --expected ... --result <你的结果>` 自测两源关联。

---

## 4. 验证清单（每 phase 必跑）

- [ ] `validate_checkpoints.py` 退出码 0（无孤儿/重复/行号漂移）
- [ ] 每个 vuln 有对应 sec，且 `expect` 与 `type` 一致
- [ ] 所有 `trace=` 节点指向真实存在的 `file:line`
- [ ] 污点流 source→sink 可读、无歧义
- [ ] 安全底线：无真实利用脚本、无真实远端连接、explanation 紧跟修复
- [ ] 样本**未出现** struts / ognl / xwork 等框架名（纯标准库自包含，可用 javax.script 模拟表达式引擎）
- [ ] 不与 `JSEF-OGNL-*` / `JSEF-SPEL-*` / `JSEF-EL-*` / `DBG-3` / `SBM-3` 维度重复（本计划仅覆盖双层求值 / 协议层 / 表达式沙箱绕过）

## 5. 反模式守卫（NOT to do）

- 不要写 `org.apache.struts2.*` / `ognl.*` / `com.opensymphony.xwork2.*` 真实依赖或调用。
- 不要重复 `JSEF-OGNL-001/002`（单层直输即 eval）与 `JSEF-SPEL-*`（单层 SpEL）的已有场景。
- 不要发明不存在的 Java API；用 `javax.script.ScriptEngine` / `Method.invoke` / `Class.forName` 等标准库模拟表达式引擎语义。
- 不要跳过 `validate_checkpoints.py` 就交付；行号漂移即门禁失败。
- L1/L2 样本不加 `trace=`（AGENTS.md：单点直连 L0–L2 不加）。
