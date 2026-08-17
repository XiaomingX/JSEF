package com.jsef.benchmark.sec;

import java.util.HashMap;
import java.util.Map;

/*
 * JSEF-Benchmark L5 — MapIndirectSpel 安全对照（SAFE 混淆样本）
 *
 * 安全做法：从 Map 取出的值同样视为不可信，不送入表达式解析；使用
 * SimpleEvaluationContext（禁方法执行）或仅作数据绑定。用于计算 TN / FP。
 *
 * CWE-917 (Expression Language Injection)。
 */
public class MapIndirectSpelSafe {

    final Map<String, String> ctx = new HashMap<>();

    public void eval(String userInput) {
        ctx.put("expr", userInput);              // 仍存入 Map
        String data = ctx.get("expr");           // 取出
        // [CHECKPOINT id=JSEF-TV-008S cwe=917 level=L5 source=userInput sink=SpelExpressionParser.parseExpression (via Map.get, data only) expect=SAFE]
        parseConstant(data);                     // 不可信 data 仅作数据，不解析表达式
    }

    // 抽象 sink（安全）：语义等价 SimpleEvaluationContext 求值固定常量
    static void parseConstant(String data) {
        System.out.println("[spel-data] " + data);
    }

    public static void main(String[] args) {
        new MapIndirectSpelSafe().eval("T(java.lang.Runtime).getRuntime().exec('id')");
    }
}
