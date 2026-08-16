/*
 * JSEF Benchmark — FP 混淆型安全样本的对照 vuln（CWE-79, 难度 L3）
 *
 * 对照样本：用户输入未转义直接拼入 HTML 输出，可 XSS。
 * 与 HtmlEscapedSafe 的 htmlEscape 转义形成 vuln/safe 对。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.vuln;

public class RawHtmlXss {

    /**
     * 危险入口：userInput 未转义直接拼入 HTML 输出。
     * @param userInput 不可信用户输入（如 "<script>alert(1)</script>"）
     */
    static String unsafe(String userInput) {
        String out = "<span>" + userInput + "</span>";
        // [CHECKPOINT id=JSEF-FP-007V cwe=79 level=L3 source=userInput sink=response output (raw) expect=VULN]
        return out;
    }
}
