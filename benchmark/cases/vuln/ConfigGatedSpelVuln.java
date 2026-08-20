package com.jsef.benchmark.vuln;

/*
 * 运行态需 JSEF 依赖：本文件引用 SpEL / 配置语义，用于静态分析 / LLM 阅读，
 * 不强求编译，但语义正确、可读。
 *
 * JSEF-Benchmark L5 — 配置/版本门控可达性链（SpEL sink）
 *
 * 难度：L5（可达性证明）。危险 SpEL 求值仅在配置开关 feature.spel=true 时执行。
 * 关键前提：该开关**默认开启**，且配置读取处（PropertySource）的值在运行态不可信
 * （可被配置注入 / 环境变量篡改）。需证明"在该配置下危险分支可达"，
 * 而纯语法 SAST 只看到 if 分支，无法断定开关为真。
 *
 * 难点/区分点：
 *   - 配置读取 → 条件分支 → SpEL sink 的可达性链；
 *   - 默认开（default=true）证明不可信配置下可达；
 *   - trace= 指向配置读取处与 SpEL sink 行。
 *
 * CWE-917 (Expression Language Injection / SpEL)。
 *
 * 安全底线：仅展示语义，Payload 仅 localhost 演示，不提供真实利用脚本。
 */
public class ConfigGatedSpelVuln {

    // 语义：配置读取（PropertySource），默认 true，运行态可被不可信来源覆盖
    private final boolean spelEnabled;

    public ConfigGatedSpelVuln(boolean spelEnabled) {
        this.spelEnabled = spelEnabled;
    }

    /**
     * 危险入口：当配置开启（默认开）时，不可信表达式进入 SpEL 求值（sink）。
     *
     * @param userExpression 不可信 SpEL 表达式
     */
    public Object handle(String userExpression) {
        if (spelEnabled) { // 配置门控：默认 true → 分支可达
            // [CHECKPOINT id=JSEF-CFG-001 cwe=917 level=L5 source=userExpression sink=SpelExpressionParser.parseExpression expect=VULN trace=benchmark/cases/vuln/ConfigGatedSpelVuln.java:38,benchmark/cases/vuln/ConfigGatedSpelVuln.java:40]
            return spelParse(userExpression); // 语义等价: SpelExpressionParser.parseExpression(userExpression).getValue()
        }
        return "spel-disabled";
    }

    // 语义桩：VULN 侧信方法名/注释声明（AGENTS.md 抽象桩约定）
    private Object spelParse(String expr) {
        System.out.println("[spel-eval] " + expr); // 语义等价: SpelExpressionParser.parseExpression(expr).getValue()
        return expr;
    }

    public static void main(String[] args) {
        new ConfigGatedSpelVuln(true).handle("T(java.lang.Runtime)"); // localhost 演示
    }
}
