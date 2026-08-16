/*
 * JSEF Benchmark 样本 — SSRF via HttpClient 安全对照 (CWE-918, L1)
 * 发起请求前校验主机在白名单。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Set;

public class SSRFHttpClientSafe {

    private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com");

    static String fetch(String url) throws Exception { // source：不可信 HTTP 参数 @RequestParam url
        URI uri = URI.create(url);
        if (!ALLOWED_HOSTS.contains(uri.getHost())) {
            throw new IllegalArgumentException("host not allowed");
        }
        HttpClient client = HttpClient.newHttpClient();
        // [CHECKPOINT id=JSEF-EXT-002S cwe=918 level=L1 source=@RequestParam url sink=allowlist validation before HttpClient.send() expect=SAFE]
        HttpRequest req = HttpRequest.newBuilder().uri(uri).build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        return resp.body();
    }
}
