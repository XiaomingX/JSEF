/*
 * JSEF Benchmark 样本 — 族B：LLM 集成安全 / Prompt Injection 安全对照（CWE-94，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义。
 *
 * 安全做法（难点/区分点）：
 *   1) 指令边界隔离：用户输入放入 <|user|> 角色分隔符，system 指令独立且不可被用户改写；
 *   2) 白名单校验：仅允许白名单内的简单指令短语，其余一律拒绝。
 * 因此 userMessage 无法覆盖 systemPrompt 系统指令边界，污点不可达危险拼接点。
 *
 * 与 vuln 侧（PromptInjectionController 直接拼接）形成 FP/TN 对照。
 */
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PromptInjectionSafe {

    private static final String SYSTEM_INSTRUCTION =
            "You are a helpful assistant. System rules are immutable.";

    // 白名单：仅允许枚举到的安全指令短语，任何"忽略/改写"类内容不在其中
    private static final java.util.Set<String> ALLOWED_PHRASES =
            java.util.Set.of("help", "summarize", "translate", "greet");

    private final LlmClientSafe llmClient;

    public PromptInjectionSafe(LlmClientSafe llmClient) {
        this.llmClient = llmClient;
    }

    @GetMapping("/benchmark/prompt-injection/safe")
    public String chat(@RequestParam String userMessage) {
        // 白名单校验：非白名单短语直接拒绝，且将输入封入 <|user|> 角色分隔符
        if (userMessage == null || !ALLOWED_PHRASES.contains(userMessage.trim())) {
            throw new IllegalArgumentException("message not in allowlist");
        }
        // [CHECKPOINT id=JSEF-PI-001S cwe=94 level=L4 source=@RequestParam userMessage sink=llmClient.chat 角色边界隔离+白名单校验 expect=SAFE]
        // system 指令与 user 输入由 <|user|> 分隔，且已过白名单，systemPrompt 不可被覆盖
        String prompt = buildIsolatedPrompt(userMessage);
        return llmClient.chat(prompt);
    }

    // 指令边界隔离：system 指令固定，用户输入封入 <|user|> 分隔符，无法改写系统指令
    private String buildIsolatedPrompt(String userMessage) {
        return SYSTEM_INSTRUCTION + "\n<|user|>\n" + userMessage + "\n<|/user|>";
    }
}
