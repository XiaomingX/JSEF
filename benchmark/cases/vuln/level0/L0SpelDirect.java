package com.jsef.benchmark.vuln;

/**
 * JSEF-Benchmark L0 — 基线（SpEL 注入，单跳直连）
 *
 * 难度：L0（基线）。source 直接传入 sink，无中间变量。
 * 用于校准 TP 基线与定位精度（CAP-03 入门级）。
 *
 * CWE-917 Expression Language Injection。
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class L0SpelDirect {

    /**
     * 单跳：不可信入参直接作为 SpEL 表达式解析（sink）。
     *
     * @param userInput 不可信输入（类比 @RequestParam expr）
     */
    public void run(String userInput) {
        // 语义等价：new SpelExpressionParser().parseExpression(userInput).getValue()
        // [CHECKPOINT id=JSEF-L0-SPEL-001 cwe=917 level=L0 source=userInput sink=SpelExpressionParser.parseExpression expect=VULN]
        parseExpression(userInput);
    }

    // 抽象 sink：框架对表达式求值。运行态需 org.springframework.expression 依赖。
    private static Object parseExpression(String expr) {
        System.out.println("[spel-eval] " + expr);
        return null;
    }

    public static void main(String[] args) {
        new L0SpelDirect().run("T(java.lang.Runtime).getRuntime().exec('echo localhost-demo')");
    }
}
