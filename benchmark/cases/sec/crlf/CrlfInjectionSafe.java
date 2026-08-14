/*
 * JSEF Benchmark 样本 — CRLF / Header 注入安全对照（CWE-93，L2）
 * 校验去除 CR/LF 后再写入响应头。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

public class CrlfInjectionSafe {

    interface Response { void addHeader(String name, String value); }

    // [SAFE] 去除 CR/LF 后再写入
    static void redirect(Response response, String userInput) {
        String safe = userInput.replace("\r", "").replace("\n", "");  // 去 CR/LF
        // source：不可信用户输入，但 CR/LF 已被剥离
        // [CHECKPOINT id=JSEF-CRLF-001S cwe=93 level=L2 source=userInput sink=response.addHeader("Location", sanitized) expect=SAFE]
        response.addHeader("Location", safe);
    }
}
