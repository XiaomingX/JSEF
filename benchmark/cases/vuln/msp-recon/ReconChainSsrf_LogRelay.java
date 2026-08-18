// [VULN]
package com.jsef.benchmark.vuln.msprecon;

/**
 * JSEF-Benchmark — 多步规划 P3：SSRF 链无害中转节点 A（日志，L4）
 *
 * 仅记录 URL，不净化、不透传业务语义改变，污点透传到 TransformRelay。
 */
public class ReconChainSsrf_LogRelay {

    private final TransformRelay transformRelay;

    public ReconChainSsrf_LogRelay(TransformRelay transformRelay) {
        this.transformRelay = transformRelay;
    }

    /** 无害中转：记录后透传。 */
    public Object relay(String url) {
        System.out.println("[audit] forwarding " + url); // 无害：仅日志
        return transformRelay.relay(url);
    }
}
