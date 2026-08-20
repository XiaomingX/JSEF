package com.jsef.benchmark.sec;

/*
 * 运行态需 JSEF 依赖：本文件引用 SpEL / 配置语义，用于静态分析 / LLM 阅读，
 * 不强求编译，但语义正确、可读。
 *
 * JSEF-Benchmark L5 — 配置/版本门控可达性链安全对照（SAFE）
 *
 * 安全做法：配置开关**默认关闭**（default=false），且存在强制白名单校验——
 * 即使配置被篡改为开启，不可信表达式也会在到达 SpEL sink 前被拒绝。
 * 危险分支不可达，SpEL 求值仅接收常量表达式。
 *
 * CWE-917 (Expression Language Injection / SpEL)。
 */
public class ConfigGatedSpelSafe {

    // 语义：配置读取，默认 false（关闭危险分支）
    private final boolean spelEnabled;

    public ConfigGatedSpelSafe(boolean spelEnabled) {
        this.spelEnabled = spelEnabled;
    }

    /**
     * 安全入口：即使配置开启，也强制白名单校验；默认关闭时分支不可达。
     *
     * @param userExpression 不可信 SpEL 表达式（会被拒绝）
     */
    public Object handleSafe(String userExpression) {
        if (spelEnabled) { // 配置门控：默认 false → 危险分支不可达
            if (!ALLOWLIST.contains(userExpression)) { // 双重防御：白名单校验
                return "rejected";
            }
            // [CHECKPOINT id=JSEF-CFG-001S cwe=917 level=L5 source=userExpression sink=SpelExpressionParser.parseExpression expect=SAFE]
            return spelConst(userExpression); // 仅白名单常量表达式可达 sink
        }
        return "spel-disabled";
    }

    private static final java.util.Set<String> ALLOWLIST =
            new java.util.HashSet<>(java.util.Arrays.asList("new java.util.Date()", "1+1"));

    // 语义桩：仅求值白名单常量表达式（SAFE 侧按实现判定为安全）
    private Object spelConst(String expr) {
        System.out.println("[spel-safe] " + expr); // 语义等价: 仅白名单常量求值
        return expr;
    }

    public static void main(String[] args) {
        new ConfigGatedSpelSafe(false).handleSafe("T(java.lang.Runtime)"); // localhost 演示
    }
}
