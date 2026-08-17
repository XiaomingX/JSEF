package com.jsef.benchmark.vuln;

import java.net.HttpURLConnection;
import java.net.URL;

/*
 * JSEF-Benchmark L3 — SSRF 经 302 重定向跳转内网
 *
 * 难度：L3（跨方法 / 隐式框架语义）。对 userUrl 做 host 白名单校验通过后，
 * HttpURLConnection 默认跟随 302 重定向，攻击者可在响应中把请求重定向到内网
 * IP，校验仅作用于初始 URL，不覆盖重定向后的目标，纯语法 SAST 难识别"跟随
 * 重定向"这一隐式框架语义。
 *
 * CWE-918 (SSRF)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 SsrfRedirectSafe.java）：禁用重定向或对每一跳目标重新校验。
 */
public class SsrfRedirect {

    /**
     * @param userUrl 用户可控 URL
     */
    public void run(String userUrl) throws Exception {
        if (!isWhitelisted(userUrl)) {
            throw new IllegalArgumentException("host not allowed");
        }
        URL url = new URL(userUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // 默认 setInstanceFollowRedirects(true)，302 可跳到内网
        // [CHECKPOINT id=JSEF-NV506 cwe=918 level=L3 source=userUrl sink=openConnection (follows 302 to intranet) expect=VULN]
        conn.getInputStream();           // 隐式跟随 302 → 内网
    }

    static boolean isWhitelisted(String u) {
        return u.startsWith("https://example.com/");
    }

    public static void main(String[] args) throws Exception {
        new SsrfRedirect().run("https://example.com/redirect?to=http://169.254.169.254/");
    }
}
