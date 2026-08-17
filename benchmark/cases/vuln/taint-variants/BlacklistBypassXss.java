package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L4 — 黑名单单次替换绕过 XSS
 *
 * 难度：L4（防护语义正确性）。代码看似做了“清洗”：把输入中的 script 替换为
 * 空串。但 replace("script","") 只替换一次且从前往后，构造
 * "<scrscriptipt>" 即可在删除 script 后重新拼出 <script>。LLM 容易把“存在
 * replace 清洗”误判为安全（误报 SAFE）。
 *
 * CWE-79 (Cross-site Scripting)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 BlacklistBypassXssSafe.java）：使用 HTML 转义 / 白名单，
 * 而非黑名单单次删除。
 */
public class BlacklistBypassXss {

    /**
     * 看似有清洗，实则单次替换可绕过。
     *
     * @param input 用户可控输入
     */
    public void render(String input) {
        String cleaned = input.replace("script", ""); // 单次替换：<scrscriptipt> 绕过
        // [CHECKPOINT id=JSEF-TV-002 cwe=79 level=L4 source=input sink=response.getWriter().print (after blacklist replace) expect=VULN trace=benchmark/cases/vuln/taint-variants/BlacklistBypassXss.java:25,benchmark/cases/vuln/taint-variants/BlacklistBypassXss.java:28]
        write(cleaned); // 绕过后的 <script> 仍输出
    }

    // 抽象 sink：语义等价 response.getWriter().print(html)
    static void write(String html) {
        System.out.println("[html-out] " + html);
    }

    public static void main(String[] args) {
        new BlacklistBypassXss().render("<scrscriptipt>alert(1)</scrscriptipt>");
    }
}
