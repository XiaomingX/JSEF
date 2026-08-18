/*
 * JSEF Benchmark 样本 — XSS 经 Sanitizer 绕过（CWE-79，L3）
 * 场景：服务端对用户评论做 HTML 净化（剥离 <script> 与 on* 事件属性），
 * 但净化器基于 BeautifulSoup 式逐标签解析，攻击者可用解析器歧义
 * （如嵌套 <script<iframe> 或属性名大小写/换行混淆）绕过净化，
 * 最终污点仍到达 HTML 响应体 sink。
 *
 * 设计意图：对抗「见净化即判安全」。净化层存在 ≠ 净化充分，
 * 正确结论需识别净化器的解析歧义仍可让污点抵达 sink。
 *
 * 借鉴 Terminal-Bench 2.1 的 break-filter-js-from-html（净化器 vs 浏览器解析器差异）。
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
package com.jsef.benchmark.vuln;

public class XssSanitizerBypass {

    /**
     * 简化版净化器：剥离已知危险标签与 on* 属性（类比 BeautifulSoup 净化）。
     * 注意：实现存在解析歧义——未处理标签名嵌套与属性名空白混淆。
     */
    static String sanitize(String html) {
        // 仅做字面黑名单替换，存在可被混淆绕过的歧义
        return html.replaceAll("(?i)<script>", "")
                   .replaceAll("(?i)</script>", "")
                   .replaceAll("(?i) on\\w+\\s*=", " ");
    }

    // [VULN] 用户输入经不充分的净化后仍直连 HTML 响应体
    static String renderComment(String userInput) {
        String cleaned = sanitize(userInput);   // 中间变量：净化层（不充分）
        // source：不可信用户评论；sink：HTML 响应体（净化歧义仍可注入脚本）
        // [CHECKPOINT id=JSEF-XSS-SAN-001 cwe=79 level=L3 source=userInput sink=HTML response body (sanitizer bypass) expect=VULN]
        return "<div class=\"comment\">" + cleaned + "</div>";
    }
}
