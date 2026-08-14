/*
 * JSEF Benchmark 样本 — EL 注入安全对照（CWE-917，L2）
 * 仅对常量表达式求值，不允许用户输入进入 EL。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

public class ElInjectionSafe {

    interface ExpressionFactory {
        Object evaluate(String expression);
    }

    // [SAFE] 仅求值固定常量表达式，用户输入不入 EL
    static Object eval(ExpressionFactory factory, String userInput) {
        String constant = "allowedConstant";   // 固定常量，非用户输入
        // source：不可信用户输入，但仅作数据不参与 EL 求值
        // [CHECKPOINT id=JSEF-EL-001S cwe=917 level=L2 source=userInput (data only) sink=ExpressionFactory.evaluate (constant expr) expect=SAFE]
        return factory.evaluate(constant);
    }
}
