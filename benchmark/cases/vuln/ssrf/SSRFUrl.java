/*
 * JSEF Benchmark 样本 — SSRF via java.net.URL (CWE-918, L1)
 * 用户输入直连到服务端请求发起，未做内网/白名单校验。
 * 安全底线：仅 localhost 演示语义，不写真实内网攻击利用。
 */
package com.jsef.benchmark.vuln;

import java.net.URL;
import java.net.HttpURLConnection;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class SSRFUrl {

    // 危险入口：@RequestParam url 直连到请求发起
    static String fetch(String url) throws Exception { // source：不可信 HTTP 参数 @RequestParam url
        // [CHECKPOINT id=JSEF-EXT-001 cwe=918 level=L1 source=@RequestParam url sink=URL.openConnection().getInputStream() expect=VULN]
        URL target = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) target.openConnection();
        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        return br.readLine(); // 服务端请求伪造，可探测内网
    }
}
