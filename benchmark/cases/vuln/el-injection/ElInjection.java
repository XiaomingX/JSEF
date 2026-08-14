/*
 * JSEF Benchmark 样本 — EL 注入（CWE-917，L2）
 * 使用标准 EL（jakarta.el）直接解析用户输入表达式。
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
package com.jsef.benchmark.vuln;

public class ElInjection {

    // 演示用 EL 求值接口（语义同 jakarta.el.ExpressionFactory）
    interface ExpressionFactory {
        Object evaluate(String expression);
    }

    // [VULN] 用户输入作为 EL 表达式被直接求值
    static Object eval(ExpressionFactory factory, String userInput) {
        // source：不可信用户输入（HTTP 请求参数）
        // [CHECKPOINT id=JSEF-EL-001 cwe=917 level=L2 source=userInput sink=ExpressionFactory.evaluate (EL evaluation) expect=VULN]
        return factory.evaluate(userInput);   // 用户输入即 EL → 表达式注入
    }
}
