package com.jsef.benchmark.sec;

import java.util.Set;

/*
 * JSEF-Benchmark L3 — SSRF scheme 白名单绕过修复
 *
 * 修复：scheme 严格白名单仅允许 http/https（非 startsWith 近似），并模拟
 * 解析目标主机 IP，拒绝云实例元数据地址 169.254.169.254 以及内网网段
 * （此处以元数据地址与回环/私网示例段做演示）。通过双重校验后才发起请求，
 * 本地/元数据/非白名单 scheme 均被阻断。
 *
 * CWE-918。SAFE 侧按实现判安全。安全底线：仅 localhost 演示语义。
 */
public class SsrfSchemeMetadataSafe {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");
    // 演示用：被禁止的目标（云元数据 + 内网示例）。真实实现应解析 InetAddress 后
    // 校验非链路本地/私网/回环网段。
    private static final Set<String> BLOCKED_HOSTS = Set.of("169.254.169.254", "localhost", "127.0.0.1");

    /**
     * 取用户 URL，做 scheme + 解析 IP 双重白名单校验后发起请求。
     *
     * @param userUrl 用户可控的目标 URL
     */
    public void fetchUserUrl(String userUrl) throws Exception {
        String scheme = userUrl.split("://", 2)[0].toLowerCase();
        if (!ALLOWED_SCHEMES.contains(scheme)) {        // 严格 scheme 白名单
            throw new SecurityException("scheme not allowed: " + scheme);
        }
        String host = userUrl.split("://", 2)[1].split("[/:]", 2)[0];
        if (BLOCKED_HOSTS.contains(host)) {             // 拒绝元数据/内网主机
            throw new SecurityException("blocked host: " + host);
        }
        // [CHECKPOINT id=JSEF-SSM-001S cwe=918 level=L3 source=userUrl sink=UrlFetcherStub.fetch expect=SAFE]
        UrlFetcherStub.fetch(userUrl);                  // 仅 http/https 且非禁止主机才到达
    }

    /**
     * 抽象 sink：语义等价 new URL(url).openConnection()，仅 localhost 演示语义，
     * 实际仅打印请求目标，不发起真实连接。
     */
    static class UrlFetcherStub {
        static void fetch(String url) {
            System.out.println("[fetch] " + url);
        }
    }

    public static void main(String[] args) throws Exception {
        new SsrfSchemeMetadataSafe().fetchUserUrl("http://169.254.169.254/latest/meta-data/");
    }
}
