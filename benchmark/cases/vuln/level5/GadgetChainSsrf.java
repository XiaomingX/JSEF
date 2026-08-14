package com.jsef.benchmark.vuln;

import java.util.function.Function;

/**
 * JSEF-Benchmark L5 — gadget chain（CWE-918 SSRF）
 *
 * 多个"单独安全"的处理器按序组合，把不可信 host 拼入 HTTP 请求 sink，并绕过内网黑名单：
 *   - UrlBuilder       ~ 把 host 拼成 URL（无害，纯拼接）
 *   - ProtocolNormalizer ~ 协议归一化（看似安全：把 "jAvaScript" 转 "javascript"）
 *   - InternalResolver ~ 内部网络解析器（黑名单校验，但被上一节点归一化绕过）
 *   - HttpSender       ~ 最终发请求（危险）
 *
 * 关键点（L5 难度）：ProtocolNormalizer 单看是"安全归一化"，但把大写协议转小写后，
 * 恰好绕过 InternalResolver 的大小写敏感黑名单（如 "JAVASCRIPT:" 未在黑名单列中），
 * 导致 file:// / javascript: 等危险协议流入 HttpSender。跨节点归一化结果被另一节点误判。
 *
 * 安全底线：本文件仅演示链式可达性语义，仅 localhost 演示，不提供真实利用载荷。
 *
 * CWE-918。
 */
public class GadgetChainSsrf {

    @FunctionalInterface
    interface Stage extends Function<String, String> {
    }

    /** URL 构造器（无害，纯拼接）。 */
    static Stage urlBuilder() {
        return host -> "http://" + host + "/api";
    }

    /** 协议归一化器（看似安全：统一小写）。 */
    static Stage protocolNormalizer() {
        // 把 "Http://" 等前缀统一为小写；但同时把黑名单遗漏的大写协议也转小写
        return url -> url.replaceFirst("(?i)^(https?|file|javascript):", m -> m.group(0).toLowerCase());
    }

    /** 内部网络解析器（黑名单，但大小写敏感漏判）。 */
    static boolean isBlocked(String url) {
        // 黑名单仅小写匹配；被上一节点归一化后的 "JAVASCRIPT:" 已变 "javascript:"
        // 这里仅示例性列出内网网段，实际黑名单漏判大写
        return url.contains("169.254.169.254") || url.startsWith("file://");
    }

    /** 危险处理器：发出请求（不可信 host 入 sink）。 */
    static Stage httpSender() {
        return url -> {
            // [CHECKPOINT id=JSEF-L5-SSRF-001 cwe=918 level=L5 source=untrusted host sink=new URL(...).openConnection expect=VULN trace=benchmark/cases/vuln/level5/GadgetChainSsrf.java:65,benchmark/cases/vuln/level5/GadgetChainSsrf.java:66,benchmark/cases/vuln/level5/GadgetChainSsrf.java:67,benchmark/cases/vuln/level5/GadgetChainSsrf.java:70]
            return send(url); // 归一化绕过黑名单后请求内网
        };
    }

    static String send(String url) {
        // 语义等价：new URL(url).openConnection()
        System.out.println("[ssrf-send] " + url);
        return "sent:" + url;
    }

    /**
     * 构造危险 gadget chain：不可信 host 经构造→归一化→黑名单（被绕过）→发请求。
     */
    public static String buildAndTrigger(String untrustedHost) {
        Stage chain = ignored -> {
            String url = urlBuilder().apply(untrustedHost);   // URL 构造
            url = protocolNormalizer().apply(url);             // 协议归一化
            if (isBlocked(url)) {                              // 黑名单（被绕过）
                url = url.replace("http://", "file://");       // 演示：转入危险协议
            }
            return httpSender().apply(url);                    // 末端 sink
        };
        return chain.apply("ignored");
    }

    public static void main(String[] args) {
        buildAndTrigger("169.254.169.254/latest/meta-data");
    }
}
