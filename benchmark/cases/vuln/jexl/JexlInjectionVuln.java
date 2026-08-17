package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L2 — JEXL 表达式注入（CWE-917）
 *
 * 难度：L2（多跳）。直接把用户可控字符串当作表达式源码交给 JEXL 求值，
 * 攻击者可执行任意 Java 表达式（如构造方法调用实现 RCE）。
 *
 * CWE-917 (Expression Language Injection)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用表达式。
 *
 * 修复要点（对照 JexlInjectionSafe.java）：表达式固定为常量，用户输入仅作数据。
 */
public class JexlInjectionVuln {

    // 抽象 sink：语义等价 org.apache.commons.jexl3.JEXLExpression.evaluate(ctx)
    static Object eval(String expr, java.util.Map<String, Object> ctx) {
        System.out.println("[jexl-eval] " + expr);
        return null;
    }

    /**
     * 危险路径：用户输入即表达式。
     *
     * @param userInput 用户可控表达式
     */
    public Object run(String userInput, java.util.Map<String, Object> ctx) {
        // [CHECKPOINT id=JSEF-NV107 cwe=917 level=L2 source=userInput sink=JEXLExpression.evaluate expect=VULN]
        return eval(userInput, ctx); // 用户字符串直接当作表达式求值
    }

    public static void main(String[] args) {
        new JexlInjectionVuln().run("''.class.forName('java.lang.Runtime')", java.util.Map.of());
    }
}
