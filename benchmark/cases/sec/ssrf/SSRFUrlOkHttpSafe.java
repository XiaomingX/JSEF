/*
 * JSEF Benchmark 样本 — SSRF via OkHttp 安全对照 (CWE-918, L2)
 * 校验主机在白名单后再发起请求。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.util.Set;

public class SSRFOkHttpSafe {

    private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com");

    static String fetch(String userUrl) throws Exception { // source：不可信 HTTP 参数 @RequestParam url
        String endpoint = userUrl;
        java.net.URI uri = java.net.URI.create(endpoint);
        if (!ALLOWED_HOSTS.contains(uri.getHost())) {
            throw new IllegalArgumentException("host not allowed");
        }
        OkHttpClient client = new OkHttpClient();
        // [CHECKPOINT id=JSEF-EXT-003S cwe=918 level=L2 source=@RequestParam url sink=allowlist validation before OkHttpClient.newCall() expect=SAFE]
        Request request = new Request.Builder().url(endpoint).build();
        try (Response resp = client.newCall(request).execute()) {
            return resp.body().string();
        }
    }
}
