/*
 * JSEF Benchmark 样本 — SSRF via java.net.http.HttpClient (CWE-918, L1)
 * 用户输入直连到 HttpClient 请求发起。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class SSRFHttpClient {

    static String fetch(String url) throws Exception { // source：不可信 HTTP 参数 @RequestParam url
        // [CHECKPOINT id=JSEF-EXT-002 cwe=918 level=L1 source=@RequestParam url sink=HttpClient.send(request) expect=VULN]
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        return resp.body(); // 服务端请求伪造
    }
}
