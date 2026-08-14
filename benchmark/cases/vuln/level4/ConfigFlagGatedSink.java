package com.jsef.benchmark.vuln;

/*
 * 运行态需 JSEF 依赖：本文件独立 benchmark 源文件，不强求编译。
 *
 * JSEF-Benchmark L4 — 状态机 / 配置开关门控危险 sink
 *
 * 难度：L4（状态机）。危险操作仅在配置开关 feature.enabled=true 时执行，
 * 但开关值本身来自不可信来源（运行时被篡改 / 配置注入），
 * 此时不可信输入会驱动危险反射/命令式 sink。纯语法 SAST 需理解"开关为真才触发 sink"
 * 这一状态机前提才能判定可达性。
 *
 * CWE-489 (Active Debug Code) / CWE-915（不当配置）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */

/**
 * JSEF-Benchmark L4 — 配置门控的危险 sink（当开关开启时危险）。
 */
public class ConfigFlagGatedSink {

    // 语义：开关值可能在运行态被不可信来源（配置注入/环境变量）设为 true
    private final boolean featureEnabled;

    public ConfigFlagGatedSink(boolean featureEnabled) {
        this.featureEnabled = featureEnabled;
    }

    /**
     * 危险入口：仅当 featureEnabled 为真时，不可信输入进入反射调用（sink）。
     *
     * @param expr 不可信输入
     */
    public Object handle(String expr) {
        if (featureEnabled) {
            // [CHECKPOINT id=JSEF-L4-CFG-001 cwe=489 level=L4 source=expr sink=ClassLoader.loadClass/reflection expect=VULN]
            return evaluate(expr); // 状态机前提满足：危险可达
        }
        return "feature-disabled";
    }

    // 抽象 sink：动态加载/反射求值（语义同 Class.forName 或 SpEL）
    private Object evaluate(String expr) {
        System.out.println("[gated-eval] " + expr);
        return null;
    }

    public static void main(String[] args) {
        new ConfigFlagGatedSink(true).handle("localhost-demo");
    }
}
