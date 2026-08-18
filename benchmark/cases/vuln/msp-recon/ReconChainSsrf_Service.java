// [VULN]
package com.jsef.benchmark.vuln.msprecon;

/**
 * JSEF-Benchmark — 多步规划 P3：SSRF 链末端节点（sink，L4）
 *
 * 对内网地址发起请求 —— 危险 sink（语义等价：RestTemplate/HttpClient 请求不可信 URL）。
 */
public class ReconChainSsrf_Service {

    /**
     * sink：对内网地址发起请求。
     */
    public Object fetchInternal(String url) {
        // 语义等价：httpClient.get(url) 访问内网资源
        System.out.println("[abstract ssrf] GET " + url);
        return "response";
    }
}
