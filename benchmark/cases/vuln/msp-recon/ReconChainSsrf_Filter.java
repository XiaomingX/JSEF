// [VULN]
package com.jsef.benchmark.vuln.msprecon;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;

/**
 * JSEF-Benchmark — 多步规划 P3：跨文件侦察链（SSRF，L4）
 *
 * 污点源头在 Filter（从请求头取 targetUrl），经两个无害中转节点后到达 Service 的内网请求 sink。
 *
 * ----------------------------------------------------------------------------
 * 长程任务子目标清单：
 *   ① 信息收集：在 Filter 定位不可信 source（请求头 X-Target-Url）。
 *   ② 调用图构建：追 targetUrl 流经 LogRelay（无害日志）到 TransformRelay（无害改写）。
 *   ③ 污点确认：TransformRelay 把 URL 透传到 ReconChainSsrf_Service。
 *   ④ 确认 sink：Service 对内网地址发起请求（SSRF）。
 * ----------------------------------------------------------------------------
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class ReconChainSsrf_Filter {

    private final LogRelay logRelay;

    public ReconChainSsrf_Filter(LogRelay logRelay) {
        this.logRelay = logRelay;
    }

    public Object doFilter(HttpServletRequest req, FilterChain chain) {
        String targetUrl = req.getHeader("X-Target-Url"); // 不可信 source
        // [CHECKPOINT id=JSEF-MSP-004 cwe=918 level=L4 source=X-Target-Url header sink=ReconChainSsrf_Service.fetchInternal expect=VULN trace=benchmark/cases/vuln/msp-recon/ReconChainSsrf_Filter.java:33,benchmark/cases/vuln/msp-recon/ReconChainSsrf_LogRelay.java:19,benchmark/cases/vuln/msp-recon/ReconChainSsrf_Service.java:14]
        return logRelay.relay(targetUrl); // 污点经无害中转流向 Service
    }
}
