package com.jsef.benchmark.sec;

import java.net.InetAddress;
import java.net.URL;

/**
 * JSEF-Benchmark Phase5-C — Blind SSRF 安全版（CWE-918，难度 L3）
 *
 * 与 BlindSsrfNoResponse 对照：同样发起请求，但先解析真实地址并拒绝内网网段，
 * 因此即使无回显也不会触达内网，是真正的 SAFE，用于计算 TN / 误报（FP）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实内网利用脚本。
 */
public class BlindSsrfNoResponseSafe {

    static String probe(String url) throws Exception {
        URL target = new URL(url);
        InetAddress addr = InetAddress.getByName(target.getHost());
        // [CHECKPOINT id=JSEF-BL-001S cwe=918 level=L3 source=request parameter url sink=URL.openConnection expect=SAFE]
        if (addr.isSiteLocalAddress() || addr.isLoopbackAddress()
                || addr.isLinkLocalAddress()) {
            throw new IllegalArgumentException("private address blocked");
        }
        target.openConnection().connect();
        return "done";
    }
}
