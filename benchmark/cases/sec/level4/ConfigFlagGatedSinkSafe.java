package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L4 — ConfigFlagGatedSink 安全对照（SAFE 混淆样本）
 *
 * 安全做法：开关默认 false 且不可由不可信来源动态改写；危险路径被关闭，
 * 不可信输入不会落到反射式 sink。用于计算 TN / FP。
 *
 * CWE-489 / CWE-915。
 */
public class ConfigFlagGatedSinkSafe {

    // 安全：开关为编译期常量 false，运行态不可被不可信输入开启
    private static final boolean FEATURE_ENABLED = false;

    public Object handle(String expr) {
        if (FEATURE_ENABLED) {
            return evaluate(expr);
        }
        // [CHECKPOINT id=JSEF-L4-CFG-001S cwe=489 level=L4 source=expr sink=ClassLoader.loadClass/reflection expect=SAFE]
        return "feature-disabled"; // 不可信 expr 永不进入危险路径
    }

    private Object evaluate(String expr) {
        System.out.println("[gated-eval] " + expr);
        return null;
    }

    public static void main(String[] args) {
        new ConfigFlagGatedSinkSafe().handle("localhost-demo");
    }
}
