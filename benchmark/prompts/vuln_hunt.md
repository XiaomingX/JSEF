# 统一漏洞挖掘提示词（Unified Vulnerability Hunting Prompt）

> 用途：本文件是 JSEF benchmark 的**统一提示词模板**。无论被测对象是哪款大模型（在 Claude Code 中切换模型）或是人工转换为 SAST 工具规则的口径，都必须使用本提示词的指令与输出约定，以保证交叉对比的公平性。
>
> 核心原则：**相同提示词 + 相同样本 = 可对比结果**。不要为特定模型改写本提示词；如需调整，应同步更新所有被测对象。

---

## 1. 任务说明（Task）

你是一名 Java 静态应用安全测试（SAST）专家。你的任务是对给定的 Java 源码或目录进行**漏洞挖掘**，识别其中真实存在的安全缺陷（true positive），同时**不要**对"看似危险但实际安全"的代码误报（false positive）。

需要覆盖的能力（对应 JSEF 区分度梯度 L0–L5）：

- Source 识别：HTTP 参数 / 请求体 / Header / 路径变量 / 反序列化输入等不可信来源。
- Sink 识别：`Runtime.exec`、`ProcessBuilder`、`eval`/`ScriptEngine`、`SpEL parseExpression`、`readObject`/`ObjectInputStream`、`JndiLookup`、`Statement`/`PreparedStatement` 拼接、文件/模板/XML/表达式引擎等危险终点。
- 污点传播：单跳、多跳（变量无断点）、间接（Map/字段/数组）、跨方法、跨文件/调用链。
- 语义约束：配置开关、白名单拦截、`SimpleEvaluationContext` 等状态机/状态前置条件。
- 框架语义：Spring 参数绑定、DataBinder、SpEL 派发等隐式 source/sink。
- gadget chain：多个单独安全的类组合形成危险可达性。

当你**确定**某条告警为真实漏洞时报告；当你**不确定**时，宁可报告并在 `message` 中标注不确定理由，**不要**为了降低误报而漏报真实漏洞。

---

## 2. 输入约定（Input）

每次运行针对**一个样本单元**（一个目录或一个文件）。输入以以下两种方式之一提供：

- **方式 A（路径）**：给定源码目录或文件路径，例如 `benchmark/cases/vuln/sqlInjection/` 或 `src/main/java/com/freedom/securitysamples/vulnerability/spelInjection/vuln/xxxController.java`。请基于提供的实际文件内容进行分析。
- **方式 B（文件内容）**：直接在对话中粘贴完整 Java 源码。

> 注意：JSEF 样本中不安全代码位于 `vuln` 包、安全对照代码位于 `sec` 包；`benchmark/cases/vendor/` 为竞品对照集。分析时以给定单元为准，不要假设未提供的上下文。

---

## 3. 输出格式（Output）

你必须输出**机器可读结果**，二选一：

### 3.1 首选：SARIF 2.1.0（精简字段）

输出一个合法 JSON，包含以下精简字段（其余字段可省略）：

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": { "driver": { "name": "<你的名称/模型标识>" } },
      "results": [
        {
          "ruleId": "CWE-917",
          "level": "error",
          "message": { "text": "用户输入直接传入 SpEL parseExpression，导致 SpEL 注入；建议改用 SimpleEvaluationContext 并限制可访问类型。" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "benchmark/cases/vuln/spelInjection/SpelController.java" },
                "region": { "startLine": 42 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

字段要求：

- `ruleId`：**必须为 CWE 编号**（如 `CWE-89`、`CWE-917`），未知以 `CWE-OTHER` 标注。
- `level`：命中真实漏洞用 `error`；疑似/不确定用 `warning`。
- `message.text`：一句话描述漏洞成因，并**在末尾给出修复建议**（见第 4 节）。
- `locations[].physicalLocation.artifactLocation.uri`：相对仓库根的路径。
- `locations[].physicalLocation.region.startLine`：**必须为精确行号**，用于定位精度评估（CAP-12）。

### 3.2 退化为 JSON 列表（仅当无法输出完整 SARIF 时）

```json
[
  {
    "id": "JSEF-SPEL-007",
    "hit": true,
    "file": "benchmark/cases/vuln/spelInjection/SpelController.java",
    "line": 42,
    "cwe": "CWE-917",
    "message": "用户输入直接传入 SpEL，建议改用 SimpleEvaluationContext。"
  }
]
```

- `hit`：布尔，表示是否判定为漏洞。
- 对于 Safe 混淆样本，若你未误报，则**不输出对应条目**；若误报则输出 `hit: true` 以便计 FP。

> 不论选哪种格式，**一条结果对应一个具体 file:line 命中点**，不要合并或泛化。

---

## 4. 修复建议要求（Remediation）

每条 `message.text` 必须包含可执行的修复建议，至少指出方向，例如：

- SQL 注入：`PreparedStatement` 参数化 / 白名单校验。
- 命令注入：避免拼接，使用固定参数列表 + 输入白名单。
- SpEL/表达式注入：使用 `SimpleEvaluationContext`、禁用 `T()` 类型引用。
- 反序列化：避免 `readObject` 不可信流，使用允许列表（allowlist）。
- JNDI/Log4j：升级依赖、禁用 `${jndi:}` 解析、移除 `JndiLookup`。

---

## 5. 运行与计时约定（Timing）

- 记录每个样本单元的 `start_ts` / `end_ts`，单位毫秒。
- 默认超时阈值 **120 秒**；超过记为"超时样本"（视为该样本整体未产出有效结果）。
- 输出之外，请同时回报：分析的样本标识、耗时（ms）、是否有超时。

---

## 6. 公平性约束（Consistency）

- 本提示词对所有被测对象一致，**禁止**针对特定模型改写任务难度或输出口径。
- 同一批样本必须用本提示词各跑一遍，产物（SARIF / JSON 列表 + 耗时）落入 `benchmark/results/<object>/` 后统一喂给 scorecard 脚本。
- 评估口径（TP/FN/FP/TN、Recall、Precision、Youden Score）以 `benchmark/expectedresults.csv` 为唯一事实源，参照 `MY_PLAN.md` Phase A/C。
