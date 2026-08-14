package com.jsef.benchmark.sec;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

/**
 * JSEF-Benchmark L5 — GadgetChainSsrf 安全对照（SAFE 混淆样本）
 *
 * 安全做法：链末端严格协议白名单 + 地址白名单校验，且归一化在黑名单之后执行，
 * 不可信 host 永不绕过校验流入 sink。用于计算 TN / FP。
 *
 * CWE-918。
 */
public class GadgetChainSsrfSafe {

    @FunctionalInterface
    interface SafeStage extends Function<String, String> {
    }

    static final List<String> ALLOWED_HOSTS = Arrays.asList("api.local", "localhost");
    static final List<String> ALLOWED_PROTO = Arrays.asList("https");

    static SafeStage urlBuilder() {
        return host -> "https://" + host + "/api";
    }

    static boolean allowlisted(String url) {
        String lower = url.toLowerCase();
        boolean protoOk = ALLOWED_PROTO.stream().anyMatch(p -> lower.startsWith(p + "://"));
        boolean hostOk = ALLOWED_HOSTS.stream().anyMatch(h -> lower.contains(h));
        boolean noInternal = !lower.contains("169.254.169.254") && !lower.startsWith("file://");
        return protoOk && hostOk && noInternal;
    }

    static String sendAllowed(String url) {
        // 语义等价：new URL(url).openConnection()，仅白名单内
        if (!allowlisted(url)) {
            System.out.println("[ssrf-safe] rejected: " + url);
            return "rejected";
        }
        System.out.println("[ssrf-safe] " + url);
        return "sent-safe:" + url;
    }

    public static String buildSafeChain(String untrustedHost) {
        SafeStage chain = ignored -> {
            String url = urlBuilder().apply(untrustedHost); // 固定 https 前缀
            // [CHECKPOINT id=JSEF-L5-SSRF-001S cwe=918 level=L5 source=untrusted host sink=new URL(...).openConnection expect=SAFE]
            return sendAllowed(url); // 链末端严格白名单校验
        };
        return chain.apply("ignored");
    }

    public static void main(String[] args) {
        buildSafeChain("169.254.169.254");
    }
}
