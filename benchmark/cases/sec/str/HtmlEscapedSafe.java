/*
 * JSEF Benchmark — FP 混淆型安全样本（CWE-79, 难度 L3）
 *
 * 样本 6：编码/转义后 safe — 输出前经 HtmlUtils.htmlEscape 转义，
 *   污点被转义为实体，无法形成可执行的 HTML/脚本，看似危险实则安全。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

import org.springframework.web.util.HtmlUtils;

public class HtmlEscapedSafe {

    /**
     * 安全入口：userInput 输出前经 htmlEscape 转义。
     * @param userInput 不可信用户输入（如 "<script>alert(1)</script>"）
     */
    static String safe(String userInput) {
        String escaped = HtmlUtils.htmlEscape(userInput);
        String out = "<span>" + escaped + "</span>";
        // [CHECKPOINT id=JSEF-FP-007 cwe=79 level=L3 source=userInput sink=response output (htmlEscape) expect=SAFE]
        return out;
    }
}
