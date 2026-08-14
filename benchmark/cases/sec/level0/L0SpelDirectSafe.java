package com.jsef.benchmark.sec;

/**
 * JSEF-Benchmark L0 — L0SpelDirect 安全对照（SAFE 混淆样本）
 *
 * 安全做法：使用 SimpleEvaluationContext（受限上下文，仅读属性/方法），
 * 不解析不可信表达式文本；或仅对常量表达式求值。用于计算 TN / FP。
 *
 * CWE-917 Expression Language Injection。
 */
public class L0SpelDirectSafe {

    /**
     * 安全求值：仅对编译期常量表达式求值，不可信输入不作为表达式文本。
     *
     * @param userInput 不可信输入（仅作数据，非表达式）
     */
    public void run(String userInput) {
        // 语义等价：new SpelExpressionParser().parseExpression("'localhost-demo'").getValue(SimpleEvaluationContext)
        // [CHECKPOINT id=JSEF-L0-SPEL-001S cwe=917 level=L0 source=userInput sink=SpelExpressionParser.parseExpression expect=SAFE]
        parseExpression("'constant-label'"); // 常量表达式，userInput 作数据不参与求值
        System.out.println("[spel-data] " + userInput);
    }

    private static Object parseExpression(String expr) {
        System.out.println("[spel-eval-safe] " + expr);
        return null;
    }

    public static void main(String[] args) {
        new L0SpelDirectSafe().run("localhost-demo");
    }
}
