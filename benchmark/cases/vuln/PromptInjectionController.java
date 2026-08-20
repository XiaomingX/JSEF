/*
 * JSEF Benchmark 样本 — 族B：LLM 集成安全 / Prompt Injection（CWE-94，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点（难点/区分点）：HTTP 请求参数 userMessage 被直接拼接进 LLM 的 systemPrompt，
 * 用户输入可覆盖系统指令边界（改写 system 角色定义的系统级指令）。区别于"模型拒答评测集"，
 * 这里是"Java 代码不安全地集成 LLM"导致的指令注入漏洞——sink 是发给 LLM 的 prompt 拼接点。
 *
 * 数据流：@RequestParam userMessage
 *    -> LlmPromptBuilder.buildSystemPrompt(userMessage)   [中间节点，trace 指向]
 *    -> llmClient.chat(prompt)                            [sink：语义等价 用户输入可覆盖系统指令边界]
 *
 * 纯语法 SAST 若不跨方法追踪 userMessage 如何进入 prompt 再进入 chat，会漏报。
 * CWE-94：代码/指令注入。
 */
package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PromptInjectionController {

    private final LlmPromptBuilder promptBuilder;
    private final LlmClientStub llmClient;

    public PromptInjectionController(LlmPromptBuilder promptBuilder, LlmClientStub llmClient) {
        this.promptBuilder = promptBuilder;
        this.llmClient = llmClient;
    }

    @GetMapping("/benchmark/prompt-injection/unsafe")
    public String chat(@RequestParam String userMessage) {
        // source：不可信 HTTP 参数 userMessage
        // [CHECKPOINT id=JSEF-PI-001 cwe=94 level=L4 source=@RequestParam userMessage sink=llmClient.chat(prompt) 用户输入可覆盖系统指令边界 expect=VULN trace=benchmark/cases/vuln/LlmPromptBuilder.java:24]
        // 语义等价: llmClient.chat(systemPrompt + userMessage) 用户输入可覆盖系统指令边界
        String prompt = promptBuilder.buildSystemPrompt(userMessage); // 污点 userMessage 经中间节点进入 prompt
        return llmClient.chat(prompt);                                // sink：拼接后的 prompt 直接交给 LLM
    }
}
