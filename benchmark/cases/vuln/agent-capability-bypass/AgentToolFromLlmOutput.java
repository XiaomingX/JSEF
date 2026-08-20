/*
 * JSEF Benchmark 样本 — AI/Agent 能力边界绕过：LLM 输出的不可信工具名直接派发（CWE-285，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点（难点/区分点）：区别于现有 3 组（AGT-001 用户直接请求、AGT-002 白名单短路、
 * AGT-003 权限自提级），本组是"LLM-工具"边界——agent 依据 LLM 生成的中间结果选择并派发工具，
 * 但 LLM 输出本身不可信（可被 prompt 注入诱导），且派发前未做能力白名单 + 参数类型校验。
 * 攻击者诱导 LLM 输出高危工具名（如 delete_file / grant_admin），agent 直接 dispatch。
 *
 * 数据流：llmOutput (不可信) -> parseToolName -> toolRegistry.dispatch(toolName) [sink]
 * 静态分析需识别"LLM 输出"是污点源，且 dispatch 前无 allowlist 防护。
 * CWE-285：不正确的授权（能力边界绕过）。
 */
package com.jsef.benchmark.vuln;

public class AgentToolFromLlmOutput {

    static final java.util.Set<String> HIGH_RISK_TOOLS =
            java.util.Set.of("delete_file", "grant_admin", "open_url_ssrf");

    private final ToolRegistryStub toolRegistry;

    public AgentToolFromLlmOutput(ToolRegistryStub toolRegistry) {
        this.toolRegistry = toolRegistry;
    }

    /**
     * agent 主循环：把 LLM 生成的中间结果解析成工具名，并派发执行。
     */
    public String runAgent(String llmOutput) {
        // source：LLM 生成的工具名（不可信中间结果，可被 prompt 注入诱导）
        String toolName = parseToolName(llmOutput);
        // [CHECKPOINT id=JSEF-AGT-004 cwe=285 level=L4 source=LLM 输出的不可信工具名 sink=toolRegistry.dispatch(toolName) 派发前无能力白名单/参数类型校验 expect=VULN]
        // 语义等价: toolRegistry.dispatch(toolName) —— 依据 LLM 输出的工具名直接派发高危工具
        return toolRegistry.dispatch(toolName);
    }

    // 从 LLM 输出中解析出工具名。LLM 输出可被注入攻击诱导，故 toolName 不可信。
    private String parseToolName(String llmOutput) {
        // 语义等价: 解析 LLM 结构化输出中的 tool_call.name 字段
        String name = llmOutput.split("\\|")[0].trim();
        return name;
    }
}
