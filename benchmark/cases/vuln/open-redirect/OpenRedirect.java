/*
 * JSEF Benchmark 样本 — 开放重定向 (CWE-601, L1)
 * @RequestParam redirectUrl 直连 response.sendRedirect，未校验目标。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

public class OpenRedirect {

    interface Response { void sendRedirect(String url) throws Exception; }

    static void go(Response response, String redirectUrl) throws Exception { // source：不可信 @RequestParam redirectUrl
        // [CHECKPOINT id=JSEF-EXT-005 cwe=601 level=L1 source=@RequestParam redirectUrl sink=response.sendRedirect(redirectUrl) expect=VULN]
        response.sendRedirect(redirectUrl); // 可跳转到任意外部站点（钓鱼）
    }
}
