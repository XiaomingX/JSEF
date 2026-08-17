package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L2 — 嵌套正则净化被绕过 (XSS)
 *
 * 难度：L2（多跳 / 无断点）。用 replaceAll("(?i)script","") 简单剔除 script，
 * 但输入 `<scr<script>ipt>` 经一次替换变为 `<script>`，嵌套结构绕过净化，
 * 污点进入响应输出。纯语法 SAST 需识别"单次替换 ≠ 充分净化"。
 *
 * CWE-79 (Cross-site Scripting)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 RegexSanitizeXssSafe.java）：输出前做 HTML 实体编码。
 */
public class RegexSanitizeXss {

    /**
     * @param input 用户可控输入
     */
    public void run(String input) {
        String cleaned = input.replaceAll("(?i)script", "");   // 嵌套绕过
        // [CHECKPOINT id=JSEF-NV508 cwe=79 level=L2 source=input sink=response output (nested regex bypass) expect=VULN]
        response(cleaned);                 // 输出到响应
    }

    // 抽象 sink：语义等价 response.getWriter().print(html)
    static void response(String html) {
        System.out.println("[response] " + html);
    }

    public static void main(String[] args) {
        new RegexSanitizeXss().run("<scr<script>ipt>alert(1)</scr<script>ipt>");
    }
}
