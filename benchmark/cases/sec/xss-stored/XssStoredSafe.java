/*
 * JSEF Benchmark 样本 — 存储型 XSS 安全对照（CWE-79，L2）
 * 取出后做 HTML 编码 / ESAPI 转义再渲染。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

public class XssStoredSafe {

    static String db = "";

    // [SAFE] 取出后做 HTML 编码
    static String storeAndRender(String userInput) {
        db = userInput;
        String fromDb = db;
        String safe = htmlEncode(fromDb);     // HTML 编码
        // source：不可信用户输入（已落库），但经 HTML 编码
        // [CHECKPOINT id=JSEF-XSSSTORED-001S cwe=79 level=L2 source=userInput (from DB) sink=response HTML body (encoded) expect=SAFE]
        return "<html><body>" + safe + "</body></html>";
    }

    // 模拟 ESAPI.encoder().encodeForHTML
    static String htmlEncode(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }
}
