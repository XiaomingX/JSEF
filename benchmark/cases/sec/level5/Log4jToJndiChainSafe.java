package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L5 — Log4jToJndiChain 安全对照（SAFE 混淆样本）
 *
 * 安全做法：不可信主机经白名单校验后才允许进入 URL；或对日志消息做 ${} 转义，
 * 杜绝 ${jndi:...} 子串形成。此处使用主机白名单，未拼出危险 JNDI key。用于计算 TN / FP。
 *
 * CWE-917 / JNDI Injection。
 */
import java.util.Arrays;
import java.util.List;

public class Log4jToJndiChainSafe {

    private static final List<String> ALLOWED_HOSTS = Arrays.asList("localhost", "127.0.0.1");

    static String jndiLookup(String key) {
        return "resolved:" + key;
    }

    public static String buildSafeChain(String untrustedHost) {
        if (!ALLOWED_HOSTS.contains(untrustedHost)) {
            throw new SecurityException("jndi host not allowed: " + untrustedHost);
        }
        // 不可信主机在白名单内，但仍不拼成 ${jndi:...}，仅作普通日志数据
        String safeMsg = "client=" + untrustedHost;
        int start = safeMsg.indexOf("${jndi:");
        String lookupKey = start >= 0 ? safeMsg.substring(start + 2) : "none";
        // [CHECKPOINT id=JSEF-L5-LOG4J-001S cwe=917 level=L5 source=multi-hop concatenated jndi key sink=JndiLookup.lookup expect=SAFE]
        return "logged:" + safeMsg + " (no lookup=" + lookupKey + ")";
    }

    public static void main(String[] args) {
        buildSafeChain("localhost");
    }
}
