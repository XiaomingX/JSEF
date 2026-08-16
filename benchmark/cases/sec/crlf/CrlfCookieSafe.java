/*
 * JSEF Benchmark 样本 — CRLF / Set-Cookie 注入安全对照 (CWE-93, L2)
 * 写入前剥离 CR/LF 字符。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

public class CrlfCookieSafe {

    interface Response { void addHeader(String name, String value); }

    static void setSessionCookie(Response response, String username) { // source：不可信用户输入 username
        String safe = username.replace("\r", "").replace("\n", "");
        String cookie = "user=" + safe + "; Path=/";
        // [CHECKPOINT id=JSEF-EXT-006S cwe=93 level=L2 source=username sink=sanitize CR/LF before addHeader expect=SAFE]
        response.addHeader("Set-Cookie", cookie);
    }
}
