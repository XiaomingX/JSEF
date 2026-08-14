package com.jsef.benchmark.vuln;

import java.net.InetAddress;
import java.net.URL;

/**
 * JSEF-Benchmark Phase5-B — 命名混淆（vendor 风格，单文件双 checkpoint，CWE-918 SSRF，难度 L3）
 *
 * 混淆点（为什么容易被误判）：
 * 方法名含 "PrivateIpCheck"/"Safe"，且确实对 IP 做了校验，看起来像标准 SSRF 防护。
 * 但校验仅判断主机名是否以 "192.168" 开头（前缀匹配），可被轻易绕过：
 *  - "192.168.0.1.example.com" 前缀即命中却解析到外网；
 *  - 十进制/八进制/十六进制 IP（如 0xC0A80001 = 192.168.0.1）绕过字符串判断；
 *  - 未对解析后的真实地址做网段校验。
 * 弱被测对象见 "ip check" 即判定安全，漏报（FN）。它实际仍是 VULN。
 *
 * 仿 OwaspStyle 单文件双 checkpoint 写法：VULN 段 + SAFE 段紧邻。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实内网利用脚本。
 */
public class ConfusionSsrfPrivateIpCheck {

    /**
     * VULN 段：仅前缀匹配 "192.168"，可绕过。
     */
    static String unsafeFetch(String url) throws Exception {
        URL target = new URL(url);
        String host = target.getHost();
        // 弱校验：仅判断前缀，无法防 "192.168.x.x.attacker.com" 或十进制 IP
        if (host.startsWith("192.168")) {
            throw new IllegalArgumentException("private ip blocked");
        }
        // [CHECKPOINT id=JSEF-NC-002 cwe=918 level=L3 source=request parameter url sink=URL.openConnection expect=VULN]
        return target.openConnection().getResponseMessage(); // 仍可请求内网（十进制 IP / 域名绕过）
    }

    /**
     * SAFE 段：解析真实地址并校验全部内网网段（10/172.16/192.168/127/169.254）。
     */
    static String safeFetch(String url) throws Exception {
        URL target = new URL(url);
        String host = target.getHost();
        InetAddress addr = InetAddress.getByName(host);
        // [CHECKPOINT id=JSEF-NC-002S cwe=918 level=L3 source=request parameter url sink=URL.openConnection expect=SAFE]
        if (addr.isSiteLocalAddress() || addr.isLoopbackAddress()
                || addr.isLinkLocalAddress()) {
            throw new IllegalArgumentException("private address blocked");
        }
        return target.openConnection().getResponseMessage(); // 严格校验后，安全
    }
}
