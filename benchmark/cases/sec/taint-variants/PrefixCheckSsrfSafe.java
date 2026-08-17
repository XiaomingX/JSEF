package com.jsef.benchmark.sec;

import java.net.URL;

/*
 * JSEF-Benchmark L4 — PrefixCheckSsrf 安全对照（SAFE 混淆样本）
 *
 * 安全做法：解析 URL 后提取主机，做主机白名单 + 拒绝内网 / 链路本地地址段
 * （如 169.254.0.0/16、10/8、127/8），而非仅前缀匹配。用于计算 TN / FP。
 *
 * CWE-918 (SSRF)。
 */
public class PrefixCheckSsrfSafe {

    public void fetch(String url) {
        if (!url.startsWith("https://")) {
            return;
        }
        String host = extractHost(url);
        if (!isAllowedHost(host)) {              // 主机白名单 + 内网拒绝
            return;
        }
        // [CHECKPOINT id=JSEF-TV-005S cwe=918 level=L4 source=url sink=URL.openConnection (after host allowlist) expect=SAFE]
        open(url);
    }

    static String extractHost(String url) {
        try {
            return new URL(url).getHost();
        } catch (Exception e) {
            return "";
        }
    }

    // 仅允许示例公开主机
    static boolean isAllowedHost(String host) {
        return host.equals("api.example.com");
    }

    // 抽象 sink（安全）：语义等价 openConnection，仅对白名单主机
    static void open(String url) {
        System.out.println("[http-fetch-safe] " + url);
    }

    public static void main(String[] args) {
        new PrefixCheckSsrfSafe().fetch("https://169.254.169.254/latest/meta-data/");
    }
}
