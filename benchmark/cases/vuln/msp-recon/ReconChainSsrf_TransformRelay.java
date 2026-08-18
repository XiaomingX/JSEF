// [VULN]
package com.jsef.benchmark.vuln.msprecon;

/**
 * JSEF-Benchmark — 多步规划 P3：SSRF 链无害中转节点 B（规范化，L4）
 *
 * 仅做 URL 规范化（大小写/去空格），不净化，污点透传到 ReconChainSsrf_Service。
 */
public class ReconChainSsrf_TransformRelay {

    private final ReconChainSsrf_Service service;

    public ReconChainSsrf_TransformRelay(ReconChainSsrf_Service service) {
        this.service = service;
    }

    /** 无害中转：规范化后透传。 */
    public Object relay(String url) {
        String normalized = url == null ? "" : url.trim().toLowerCase();
        return service.fetchInternal(normalized);
    }
}
