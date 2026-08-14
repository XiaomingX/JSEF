package com.jsef.benchmark.sec;

import java.util.function.Function;

/**
 * JSEF-Benchmark L5 — GadgetChainJdbc 安全对照（SAFE 混淆样本）
 *
 * 安全做法：链末端不使用不可信片段拼出的 URL；JDBC URL 为编译期固定常量，
 * 不可信输入仅作为查询参数经白名单校验后传入，不进入连接串拼接。用于计算 TN / FP。
 *
 * CWE-89 / CWE-502。
 */
public class GadgetChainJdbcSafe {

    @FunctionalInterface
    interface SafeConverter extends Function<String, String> {
    }

    static SafeConverter constant(String value) {
        return x -> value;
    }

    // 安全：固定 JDBC URL 常量，不可信输入不参与拼接
    static final String FIXED_URL = "jdbc:mysql://localhost/demo?useSSL=false";

    static String connectFixed(String param) {
        // 语义等价：DriverManager.getConnection(FIXED_URL)，param 仅作数据
        System.out.println("[jdbc-connect-safe] " + FIXED_URL + " param=" + param);
        return "connected-safe";
    }

    public static String buildSafeChain(String untrusted) {
        SafeConverter chain = input -> {
            String url = constant(FIXED_URL).apply(input); // 常量 URL，丢弃不可信
            // [CHECKPOINT id=JSEF-L5-JDBC-001S cwe=89 level=L5 source=chained url fragment sink=DriverManager.getConnection expect=SAFE]
            return connectFixed(untrusted); // 不可信仅作数据，不拼入 URL
        };
        return chain.apply(untrusted);
    }

    public static void main(String[] args) {
        buildSafeChain("attacker-controlled");
    }
}
