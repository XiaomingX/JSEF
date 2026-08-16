/*
 * JSEF Benchmark 样本 — SSRF via OkHttp (CWE-918, L2)
 * 用户输入经 url 变量中转后传入 OkHttp 请求，多跳但无断点校验。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class SSRFOkHttp {

    static String fetch(String userUrl) throws Exception { // source：不可信 HTTP 参数 @RequestParam url
        String endpoint = userUrl; // 中间变量，无校验
        OkHttpClient client = new OkHttpClient();
        // [CHECKPOINT id=JSEF-EXT-003 cwe=918 level=L2 source=@RequestParam url sink=OkHttpClient.newCall(request).execute() expect=VULN]
        Request request = new Request.Builder().url(endpoint).build();
        try (Response resp = client.newCall(request).execute()) {
            return resp.body().string(); // 服务端请求伪造
        }
    }
}
