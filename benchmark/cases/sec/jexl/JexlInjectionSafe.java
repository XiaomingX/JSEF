package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L2 — JEXL 表达式注入修复（CWE-917）
 *
 * 修复：表达式固定为常量模板，用户值仅以变量形式注入上下文，绝不拼接进表达式串。
 *
 * CWE-917 (Expression Language Injection)。
 */
public class JexlInjectionSafe {

    static final String FIXED_EXPR = "name.toUpperCase()"; // 常量表达式

    static Object eval(String expr, java.util.Map<String, Object> ctx) {
        System.out.println("[jexl-eval] " + expr);
        return null;
    }

    /**
     * 安全路径：表达式固定，用户输入仅作数据。
     *
     * @param userInput 用户可控数据
     */
    public Object run(String userInput, java.util.Map<String, Object> ctx) {
        java.util.Map<String, Object> safe = new java.util.HashMap<>(ctx);
        safe.put("name", userInput); // 用户输入仅作为数据变量
        // [CHECKPOINT id=JSEF-NV107S cwe=917 level=L2 source=userInput sink=JEXLExpression.evaluate (fixed expr, input as data only) expect=SAFE]
        return eval(FIXED_EXPR, safe); // 表达式固定，不可被用户输入改变
    }

    public static void main(String[] args) {
        new JexlInjectionSafe().run("Bob", java.util.Map.of());
    }
}
