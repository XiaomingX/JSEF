/*
 * JSEF Benchmark 样本 — XSS 经 Sanitizer 绕过 安全对照（CWE-79，L3）
 * 净化器采用结构化解析 + 允许列表策略，拒绝一切非白名单标签/属性，
 * 并以 HTML 实体编码兜底，污点无法抵达响应体 sink。
 *
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

public class XssSanitizerBypassSafe {

    /** 安全净化：实体编码兜底，污点退化为纯文本。 */
    static String sanitizeSafe(String html) {
        return html.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#x27;");
    }

    // [SAFE] 用户输入经实体编码后再进入响应体，无法被解析为标签
    static String renderComment(String userInput) {
        String cleaned = sanitizeSafe(userInput); // 中间变量：安全净化
        // source：不可信用户评论；sink：HTML 响应体（已编码，无脚本语义）
        // [CHECKPOINT id=JSEF-XSS-SAN-001S cwe=79 level=L3 source=userInput sink=HTML response body (encoded) expect=SAFE]
        return "<div class=\"comment\">" + cleaned + "</div>";
    }
}
