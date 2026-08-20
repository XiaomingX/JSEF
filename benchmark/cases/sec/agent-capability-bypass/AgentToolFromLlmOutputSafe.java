/*
 * JSEF Benchmark 样本 — AI/Agent 能力边界绕过：工具派发强制白名单 + 参数类型校验（safe 对照，CWE-285，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义。
 *
 * 安全做法（难点/区分点）：即使 LLM 输出的工具名不可信，派发前必须
 *   1) 能力白名单：仅允许枚举到的低危工具，高危工具不在其中；
 *   2) 参数类型校验：工具名必须匹配严格命名约定（防止注入非法工具）。
 * 任何未过白名单的工具名都会抛异常，LLM 输出无法诱导高危派发。
 *
 * 与 vuln 侧（AgentToolFromLlmOutput 直接 dispatch）形成 FP/TN 对照。
 */
package com.jsef.benchmark.sec;

public class AgentToolFromLlmOutputSafe {

    // 能力白名单：agent 仅被允许调用这些低危只读工具
    static final java.util.Set<String> ALLOWED_TOOLS =
            java.util.Set.of("search", "summarize", "get_weather");

    private final ToolRegistrySafe toolRegistry;

    public AgentToolFromLlmOutputSafe(ToolRegistrySafe toolRegistry) {
        this.toolRegistry = toolRegistry;
    }

    /**
     * agent 主循环（安全版）：LLM 输出的工具名必须先过能力白名单 + 参数类型校验，
     * 通过后才派发。高危工具名（delete_file 等）不在白名单，必被拒绝。
     */
    public String runAgent(String llmOutput) {
        String toolName = parseToolName(llmOutput);
        // 能力白名单 + 参数类型校验：非法工具名直接拒绝，不进 dispatch
        if (toolName == null || !ALLOWED_TOOLS.contains(toolName)) {
            throw new IllegalArgumentException("tool not in allowlist: " + toolName);
        }
        // [CHECKPOINT id=JSEF-AGT-004S cwe=285 level=L4 source=LLM 输出的不可信工具名 sink=toolRegistry.dispatch 能力白名单+参数类型校验后才派发 expect=SAFE]
        // 已过 allowlist + 类型校验，LLM 输出无法诱导高危派发
        return toolRegistry.dispatch(toolName);
    }

    private String parseToolName(String llmOutput) {
        // 语义等价: 解析 LLM 结构化输出中的 tool_call.name 字段
        String name = llmOutput.split("\\|")[0].trim();
        return name;
    }
}
