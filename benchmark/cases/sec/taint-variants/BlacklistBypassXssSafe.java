package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L4 — BlacklistBypassXss 安全对照（SAFE 混淆样本）
 *
 * 安全做法：对用户输入做 HTML 转义（< > & " ' 等转义为实体），
 * 根本性阻断标签注入，而非黑名单单次删除。用于计算 TN / FP。
 *
 * CWE-79 (Cross-site Scripting)。
 */
public class BlacklistBypassXssSafe {

    public void render(String input) {
        String escaped = htmlEscape(input); // 正确：实体转义，不可绕过
        // [CHECKPOINT id=JSEF-TV-002S cwe=79 level=L4 source=input sink=response.getWriter().print (after html-escape) expect=SAFE]
        write(escaped);
    }

    // 抽象 sink（安全）：语义等价响应输出转义后内容
    static void write(String html) {
        System.out.println("[html-out-safe] " + html);
    }

    // 语义等价：Spring HtmlUtils.htmlEscape / Apache commons-text 转义
    static String htmlEscape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }

    public static void main(String[] args) {
        new BlacklistBypassXssSafe().render("<scrscriptipt>alert(1)</scrscriptipt>");
    }
}
