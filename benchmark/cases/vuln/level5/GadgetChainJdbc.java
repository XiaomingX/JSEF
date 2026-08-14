package com.jsef.benchmark.vuln;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * JSEF-Benchmark L5 — gadget chain（JDBC 任意 URL 连接）
 *
 * 多个"单独安全"的转换器类组合触发 JDBC 任意 URL 连接：
 *   - ConstantConverter  ~ 返回常量（无害）
 *   - ConcatConverter    ~ 字符串拼接（无害）
 *   - UrlConverter       ~ 把拼接结果当作 JDBC URL 交给 DriverManager.getConnection（危险）
 *
 * 关键点（L5 难度）：每个转换器单看都"无害"——常量、拼接、取字段。
 * 但当它们经 ChainedConverter 组合、并把链末端输出送入 DriverManager.getConnection(url) 时，
 * 不可信片段一旦参与拼接链，就能拼出攻击者控制的 JDBC URL（含 autoDeserialize/恶意外链），
 * 形成"任意 URL 连接"可达性。纯语法 SAST 难以识别跨类组合才危险的链路。
 *
 * 安全底线：本文件仅演示链式可达性语义，仅 localhost 演示，不提供真实利用载荷。
 *
 * CWE-89 (SQL Injection via JDBC URL) / CWE-502。
 */
public class GadgetChainJdbc {

    /** 模拟链式转换器（标准库 Function 语义）。 */
    @FunctionalInterface
    interface Converter extends Function<String, String> {
    }

    static Converter constant(String value) {
        return x -> value;
    }

    static Converter concat(String suffix) {
        return x -> x + suffix;
    }

    /** 危险转换器：把输入作为 JDBC URL 连接（仅 localhost 演示语义）。 */
    static Converter jdbcUrl() {
        return url -> {
            // [CHECKPOINT id=JSEF-L5-JDBC-001 cwe=89 level=L5 source=chained url fragment sink=DriverManager.getConnection expect=VULN]
            return connect(url); // 不可信片段拼出的 URL 触发连接
        };
    }

    static String connect(String url) {
        // 语义等价：DriverManager.getConnection(url)
        System.out.println("[jdbc-connect] " + url);
        return "connected:" + url;
    }

    /**
     * 构造危险 gadget chain：不可信片段经常量+拼接组合出 JDBC URL，末端连接。
     */
    public static String buildAndTrigger(String untrustedFragment) {
        Converter chain = input -> {
            String cur = constant("jdbc:mysql://localhost/").apply(input); // 常量前缀
            cur = concat(untrustedFragment).apply(cur);                    // 不可信片段拼入
            cur = concat("?autoDeserialize=true").apply(cur);              // 危险参数
            return jdbcUrl().apply(cur);                                    // 末端 sink
        };
        return chain.apply(untrustedFragment);
    }

    public static void main(String[] args) {
        buildAndTrigger("demo");
    }
}
