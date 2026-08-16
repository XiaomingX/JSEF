/*
 * JSEF Benchmark 样本 — 开放重定向安全对照 (CWE-601, L1)
 * 仅允许站内相对路径或白名单域名后再重定向。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import java.util.Set;

public class OpenRedirectSafe {

    interface Response { void sendRedirect(String url) throws Exception; }

    private static final Set<String> ALLOWED = Set.of("example.com", "www.example.com");

    static void go(Response response, String redirectUrl) throws Exception { // source：不可信 @RequestParam redirectUrl
        // 仅允许站内相对路径或以白名单域名开头
        if (redirectUrl.startsWith("/") && !redirectUrl.startsWith("//")) {
            // [CHECKPOINT id=JSEF-EXT-005S cwe=601 level=L1 source=@RequestParam redirectUrl sink=allowlist validation before sendRedirect expect=SAFE]
            response.sendRedirect(redirectUrl);
            return;
        }
        for (String host : ALLOWED) {
            if (redirectUrl.startsWith("https://" + host + "/")) {
                response.sendRedirect(redirectUrl);
                return;
            }
        }
        throw new IllegalArgumentException("redirect target not allowed");
    }
}
