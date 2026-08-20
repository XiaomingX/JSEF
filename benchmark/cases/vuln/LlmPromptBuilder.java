/*
 * JSEF Benchmark 样本 — 族B：LLM 集成安全 / Prompt Injection 中间节点（CWE-94，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义。
 *
 * 中间节点：把不可信 userMessage 直接拼进 systemPrompt。
 * 危险点：未做指令边界隔离（无 <|user|>/<|assistant|> 角色分隔，无白名单），
 * 用户输入的 "ignore previous instructions" 之类内容可直接改写系统指令。
 *
 * 本类是 PromptInjectionController 的 trace 中间节点。
 */
package com.jsef.benchmark.vuln;

public class LlmPromptBuilder {

    private static final String SYSTEM_INSTRUCTION =
            "You are a helpful assistant. Only follow system-level rules.";

    /**
     * 危险：直接把不可信用户输入拼进 systemPrompt。
     * 返回的 prompt 同时含系统指令与用户输入，两者无边界，用户可覆盖系统指令。
     */
    public String buildSystemPrompt(String userMessage) {
        // 未做角色边界隔离：system 指令与 user 输入在同一字符串中无分隔符
        String prompt = SYSTEM_INSTRUCTION + "\n" + userMessage; // 污点 userMessage 直接注入 prompt
        return prompt;
    }
}
