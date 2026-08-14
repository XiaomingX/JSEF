package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L5 — Spring4ShellChain 安全对照（SAFE 混淆样本）
 *
 * 安全做法：使用 @InitBinder 禁止绑定 class.* / module.* / classLoader 等危险路径，
 * 或改用 SimpleEvaluationContext 且不对不可信属性值做表达式求值。用于计算 TN / FP。
 *
 * CWE-917 Expression Language Injection。
 */
import org.springframework.web.bind.annotation.RequestParam;

public class Spring4ShellChainSafe {

    public static class Module { public Object classLoader; }
    public static class Clazz { public Module module; }

    public void bindAndEval(@RequestParam("class.module.classLoader") String propPath) {
        // 安全：禁止危险属性路径绑定，propPath 仅作数据，不做 SpEL 求值
        if (propPath != null && propPath.contains("class.module")) {
            throw new SecurityException("binding blocked: dangerous class.module path");
        }
        // [CHECKPOINT id=JSEF-L5-S4S-001S cwe=917 level=L5 source=class.module.classLoader path sink=SpelExpressionParser.parseExpression expect=SAFE]
        System.out.println("[spel-data] " + propPath); // 不可信值不参与表达式求值
    }

    public static void main(String[] args) {
        new Spring4ShellChainSafe().bindAndEval("localhost-demo");
    }
}
