/*
 * JSEF Benchmark 样本 — 族B：LLM 集成安全 / 语义桩（桩方法声明真实语义）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义。
 *
 * 语义桩：本方法体仅 println，不真实调用外部 LLM SDK（不发明不存在的 API）。
 * 被测工具应信任方法上的 "// 语义等价: ..." 声明、按语义报告漏洞，
 * 而非逐字执行桩体。
 */
package com.jsef.benchmark.vuln;

public class LlmClientStub {

    /**
     * 语义等价: llmClient.chat(prompt) —— 将 prompt 发送给 LLM 并返回其回复。
     * 桩体仅演示语义，不真实发送网络请求。
     */
    public String chat(String prompt) {
        // 语义等价: 将 prompt 交给 LLM 服务端处理
        System.out.println("[llm-chat] " + prompt);
        return "assistant reply to: " + prompt;
    }
}
