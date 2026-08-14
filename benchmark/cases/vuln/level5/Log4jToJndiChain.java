package com.jsef.benchmark.vuln;

/*
 * 运行态需 JSEF 依赖：本文件为独立 benchmark 源文件，不直接依赖真实 log4j，
 * 用注释 + 模拟方法表达 JndiLookup.lookup 风格的 sink。仅用于静态分析 / LLM 阅读。
 *
 * JSEF-Benchmark L5 — gadget chain（Log4j -> JNDI 注入链）
 *
 * 难度：L5（gadget chain）。多个单独"无害"的字符串片段经多跳拼接组合，
 * 最终拼出 ${jndi:ldap://...} 子串，再经日志格式解析触发 JndiLookup.lookup（sink）：
 *   - FragmentA：常量前缀 "${jndi:"
 *   - FragmentB：不可信主机输入（攻击者可控）
 *   - FragmentC：常量后缀 "}" 与 LDAP 协议
 *   三段经链式拼接器组合 -> 形成完整 JNDI lookup key -> 交给 jndiLookup（sink）
 *
 * 关键点：单段都无害，组合后才形成 ${jndi:...} 危险子串。纯语法 SAST 难识别跨片段拼接才危险。
 *
 * CWE-917 Expression Language / JNDI Injection (Log4j)。
 * 安全底线：仅展示拼接链语义，Payload 仅 localhost 演示，不提供真实利用脚本。
 */

/**
 * JSEF-Benchmark L5 — 多跳字符串拼接 + JNDI lookup 组合的 gadget chain。
 */
public class Log4jToJndiChain {

    /** 模拟 JndiLookup 风格的 sink。 */
    static String jndiLookup(String key) {
        return "resolved:" + key; // SINK（语义）
    }

    /** 链式拼接器：把多段组合成最终字符串。 */
    interface Frag extends java.util.function.Function<String, String> {
    }

    static Frag frag(String value) {
        return x -> x + value;
    }

    /**
     * 构造危险链：不可信主机片段拼入 JNDI 协议串后触发 lookup。
     */
    public static String buildAndTrigger(String untrustedHost) {
        // 各片段单看无害：常量前缀、不可信主机、常量后缀
        Frag chain = input -> {
            String cur = frag("${jndi:ldap://").apply(input); // 常量协议前缀
            cur = frag(untrustedHost).apply(cur);             // 不可信主机拼入
            cur = frag("/evil}").apply(cur);                  // 常量后缀
            return cur;
        };
        String key = chain.apply(""); // 拼出 "${jndi:ldap://<untrustedHost>/evil}"

        // 日志框架对格式串做 ${} 解析，分派到 JndiLookup
        int start = key.indexOf("${jndi:");
        int end = key.indexOf('}', start);
        String lookupKey = key.substring(start + 2, end);
        // [CHECKPOINT id=JSEF-L5-LOG4J-001 cwe=917 level=L5 source=multi-hop concatenated jndi key sink=JndiLookup.lookup expect=VULN]
        return jndiLookup(lookupKey);
    }

    public static void main(String[] args) {
        buildAndTrigger("localhost:1389");
    }
}
