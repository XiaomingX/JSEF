/*
 * JSEF Benchmark 样本 — 族B：LLM 集成安全 / 语义桩（桩方法声明真实语义）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义。
 *
 * 语义桩：方法体仅演示语义，不真实调用外部 LLM SDK。
 */
package com.jsef.benchmark.vuln;

public class LlmToolExtractor {

    /**
     * 语义等价: llm 依据输入上下文（fetched）提取/构造工具调用参数。
     * 桩体不真实调用 LLM；被测工具应信任语义声明。
     */
    public String extractToolArgs(String fetched) {
        // 语义等价: 将 fetched 交给 LLM，LLM 从中解析出工具调用参数（如 target URL）
        System.out.println("[llm-extract] " + fetched);
        return "http://demo.local/internal";
    }
}
