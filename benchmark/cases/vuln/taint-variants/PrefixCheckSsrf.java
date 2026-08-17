package com.jsef.benchmark.vuln;

import java.net.URL;

/*
 * JSEF-Benchmark L4 — 前缀 / 弱正则校验 SSRF
 *
 * 难度：L4（防护语义正确性）。代码用 startsWith("https://") 做“校验”，给人
 * “已限制协议”的错觉。但仅校验前缀无法阻止：
 *   - 内网主机：https://169.254.169.254/（元数据服务）
 *   - 用户混淆：https://attacker@internal/（@ 前为用户info）
 *   - 控制字符 / 混合大小写变体
 * LLM 容易把“startsWith 校验”误报为 SAFE。
 *
 * CWE-918 (SSRF)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 PrefixCheckSsrfSafe.java）：解析主机并做主机白名单 /
 * 地址段拒绝，而非仅前缀匹配。
 */
public class PrefixCheckSsrf {

    /**
     * 仅前缀校验，可被绕过访问内网。
     *
     * @param url 用户可控 URL
     */
    public void fetch(String url) {
        if (url.startsWith("https://")) {        // 弱校验：仅看前缀
            // [CHECKPOINT id=JSEF-TV-005 cwe=918 level=L4 source=url sink=URL.openConnection (after startsWith prefix check) expect=VULN trace=benchmark/cases/vuln/taint-variants/PrefixCheckSsrf.java:30,benchmark/cases/vuln/taint-variants/PrefixCheckSsrf.java:34]
            open(url);                            // 仍可访问内网/元数据
        }
    }

    // 抽象 sink：语义等价 new URL(url).openConnection()
    static void open(String url) {
        System.out.println("[http-fetch] " + url);
    }

    public static void main(String[] args) throws Exception {
        new PrefixCheckSsrf().fetch("https://169.254.169.254/latest/meta-data/");
    }
}
