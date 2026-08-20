/*
 * JSEF Benchmark 样本 — 族B：LLM 集成安全 / 语义桩（桩方法声明真实语义）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义。
 *
 * 语义桩：工具调用器。方法体仅 println，不真实发起网络请求/打开 URL。
 * 被测工具应信任 "// 语义等价: ..." 声明、按语义报告 SSRF。
 */
package com.jsef.benchmark.vuln;

public class ToolInvokerStub {

    /**
     * 语义等价: 按 toolArgs 调用对应工具（本场景为打开 URL，SSRF sink）。
     * 桩体不真实打开 URL。
     */
    public String call(String toolArgs) {
        // 语义等价: 使用 toolArgs 作为目标 URL 发起请求（SSRF）
        System.out.println("[tool-call] open_url " + toolArgs);
        return "opened: " + toolArgs;
    }
}
