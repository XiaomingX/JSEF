/*
 * JSEF Benchmark 样本 — DOM 型 XSS 安全对照（CWE-79，L2）
 * 使用 textContent 或转义后再写入 DOM。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

public class XssDomSafe {

    // [SAFE] 使用 textContent，且服务端做 JS 字符串转义
    static String renderPage(String userInput) {
        String safe = jsEscape(userInput);    // JS 字符串转义
        // source：不可信用户输入，但已转义后作为纯文本写入
        // [CHECKPOINT id=JSEF-XSSDOM-001S cwe=79 level=L2 source=userInput sink=document.textContent (escaped) expect=SAFE]
        return "<html><body><script>var x = \"" + safe + "\"; document.getElementById('out').textContent = x;</script></body></html>";
    }

    static String jsEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("<", "\\u003c");
    }
}
