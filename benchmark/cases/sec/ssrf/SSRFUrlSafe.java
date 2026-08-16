/*
 * JSEF Benchmark 样本 — SSRF via java.net.URL 安全对照 (CWE-918, L1)
 * 校验 URL 主机在白名单内、非内网地址后再发起请求。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import java.net.URL;
import java.net.HttpURLConnection;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Set;

public class SSRFUrlSafe {

    private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com", "cdn.example.com");

    static String fetch(String url) throws Exception { // source：不可信 HTTP 参数 @RequestParam url
        URL target = new URL(url);
        String host = target.getHost();
        if (!ALLOWED_HOSTS.contains(host)) { // 白名单校验
            throw new IllegalArgumentException("host not allowed: " + host);
        }
        // [CHECKPOINT id=JSEF-EXT-001S cwe=918 level=L1 source=@RequestParam url sink=allowlist validation before URL.openConnection() expect=SAFE]
        HttpURLConnection conn = (HttpURLConnection) target.openConnection();
        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        return br.readLine();
    }
}
