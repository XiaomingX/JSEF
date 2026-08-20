/*
 * JSEF Benchmark 样本 — 族B：LLM 集成安全 / LLM 间接注入（Indirect Prompt Injection，CWE-918，L5）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点（难点/区分点）：攻击者不直接操控工具调用参数，而是把恶意指令注入外部文档/网页内容。
 * LLM 拉取该外部内容并"中毒"，依据被污染上下文生成工具调用参数，最终触发 SSRF（打开攻击者指定 URL）。
 * 这是"外部数据源污染 LLM 上下文 → 工具误调用"的多节点 gadget 链（L5）。
 *
 * 数据流（多节点 gadget chain）：
 *   ExternalContentSource.fetchContent(url)   [辅助类：拉取外部网页，可被攻击者注入指令]
 *     -> llm.extractToolArgs(fetched)         [LLM 依据被污染上下文提取工具参数]
 *        -> toolInvoker.call(agentExtractedArgs) [sink：语义等价 参数被外部污染 → 打开任意 URL（SSRF）]
 *
 * 纯语法 SAST 需跨文件 + 跨"外部内容→LLM 提取→工具调用"多跳追踪污点。
 * CWE-918：服务器端请求伪造（SSRF）。
 */
package com.jsef.benchmark.vuln;

public class LlmIndirectInjectionVuln {

    private final ExternalContentSource contentSource;
    private final LlmToolExtractor llm;
    private final ToolInvokerStub toolInvoker;

    public LlmIndirectInjectionVuln(ExternalContentSource contentSource,
                                    LlmToolExtractor llm,
                                    ToolInvokerStub toolInvoker) {
        this.contentSource = contentSource;
        this.llm = llm;
        this.toolInvoker = toolInvoker;
    }

    /**
     * 处理外部文档触发的 agent 任务：拉取外部内容 -> LLM 提取工具参数 -> 调工具。
     * 外部内容可能被攻击者注入 "call tool open_url with http://attacker/..." 之类的指令。
     */
    public String processExternalDoc(String docUrl) {
        // source：外部文档/网页内容（可被攻击者注入指令）
        String fetched = contentSource.fetchContent(docUrl);           // 拉取外部内容（污染源）
        String agentExtractedArgs = llm.extractToolArgs(fetched);      // LLM 依据被污染上下文提取参数
        // [CHECKPOINT id=JSEF-PI-002 cwe=918 level=L5 source=外部文档/网页内容(docUrl) sink=toolInvoker.call(agentExtractedArgs) 参数被外部污染 expect=VULN trace=benchmark/cases/vuln/ExternalContentSource.java:22]
        // 语义等价: toolInvoker.call(agentExtractedArgs) agent 提取的参数被外部污染 -> 打开攻击者 URL（SSRF）
        return toolInvoker.call(agentExtractedArgs);                   // sink：被污染参数直达工具调用（SSRF）
    }
}
