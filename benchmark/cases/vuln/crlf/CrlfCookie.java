/*
 * JSEF Benchmark 样本 — CRLF / Set-Cookie 注入 (CWE-93, L2)
 * 用户输入拼接到 Set-Cookie 值，含 \r\n 可注入额外头。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

public class CrlfCookie {

    interface Response { void addHeader(String name, String value); }

    // 危险：用户名直接拼入 Set-Cookie，未去 CR/LF
    static void setSessionCookie(Response response, String username) { // source：不可信用户输入 username
        String cookie = "user=" + username + "; Path=/";
        // [CHECKPOINT id=JSEF-EXT-006 cwe=93 level=L2 source=username sink=response.addHeader("Set-Cookie", value) expect=VULN]
        response.addHeader("Set-Cookie", cookie); // 含 \r\n → 头注入
    }
}
