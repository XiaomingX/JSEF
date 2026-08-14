package com.jsef.benchmark.vuln;

import java.net.URL;

/**
 * JSEF-Benchmark Phase5-C — Blind SSRF（CWE-918，难度 L3）
 *
 * 混淆点（为什么容易被误判）：
 * 方法发起对内网地址的请求，但"不返回响应内容"给调用方，仅返回固定 "done"。
 * 弱被测对象可能据此认为"没有回显就不是漏洞"（误判为 SAFE / FP 风险在对照段）。
 * 然而 SSRF 的危害并不依赖回显：即使无回显，攻击者可借请求触发内网动作
 * （如访问云元数据 169.254.169.254、打内网管理端口、做端口探测）。
 * 因此 Blind SSRF 仍是真实 VULN，漏报即 FN。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实内网利用脚本。
 */
public class BlindSsrfNoResponse {

    /**
     * 危险入口：用户输入作为 URL 直接请求，无白名单校验，且不回显。
     */
    static String probe(String url) throws Exception {
        // [CHECKPOINT id=JSEF-BL-001 cwe=918 level=L3 source=request parameter url sink=URL.openConnection expect=VULN]
        URL target = new URL(url); // 可达内网（如 http://169.254.169.254/）
        target.openConnection().connect(); // 发起请求但丢弃响应
        return "done"; // 调用方无回显，但请求已发出
    }
}
