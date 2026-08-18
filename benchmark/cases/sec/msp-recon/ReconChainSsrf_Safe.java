// [VULN]（安全对照样本，expect=SAFE）
package com.jsef.benchmark.sec.msprecon;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;

/**
 * JSEF-Benchmark — 多步规划 P3 安全对照 (难度 L4, CWE-918, expect=SAFE)
 *
 * 修复思路（对照 vuln 版本 ReconChainSsrf_*）：
 *   对内网请求的目标地址做白名单校验，不可信 URL 被拒，无法到达 fetchInternal sink。
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class ReconChainSsrf_Safe {

    private static final java.util.Set<String> ALLOWED_HOSTS =
            java.util.Set.of("api.internal", "localhost");

    public Object doFilter(HttpServletRequest req, FilterChain chain) {
        String targetUrl = req.getHeader("X-Target-Url");
        // [CHECKPOINT id=JSEF-MSP-004S cwe=918 level=L4 source=X-Target-Url header sink=host allowlist reject expect=SAFE]
        if (targetUrl == null || !ALLOWED_HOSTS.contains(hostOf(targetUrl))) {
            return "blocked"; // 不可信主机被拒，无法到达 sink
        }
        System.out.println("[abstract ssrf] GET " + targetUrl);
        return "response";
    }

    private static String hostOf(String url) {
        int idx = url.indexOf("://");
        String rest = idx >= 0 ? url.substring(idx + 3) : url;
        int slash = rest.indexOf('/');
        return slash >= 0 ? rest.substring(0, slash) : rest;
    }
}
