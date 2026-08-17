package com.jsef.benchmark.vuln;

import java.util.HashMap;
import java.util.Map;

/*
 * JSEF-Benchmark L5 — 污点经 Map / 字段间接后进入 SpEL
 *
 * 难度：L5（gadget chain 风格 / 间接传播）。不可信输入先存入 Map，再经
 * map.get(key) 取出（间接节点），最终送入 SpEL 表达式求值（sink）。中间有
 * “存 Map → 取 Map → 表达式”两个间接跳板，纯语法 SAST 难以把 Map.get 的返回值
 * 与原始 source 关联，易断链漏报。区别于现有 L0/L4 SpEL 直连 / 拦截器场景。
 *
 * CWE-917 (Expression Language Injection)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 MapIndirectSpelSafe.java）：从 Map 取出的值同样视为不可信，
 * 不送入表达式解析，或仅用作数据绑定。
 */
public class MapIndirectSpel {

    // 间接存储：不可信输入经此中转
    final Map<String, String> ctx = new HashMap<>();

    /**
     * 不可信输入经 Map 中转后进入 SpEL。
     *
     * @param userInput 用户可控输入
     */
    public void eval(String userInput) {
        ctx.put("expr", userInput);              // 间接节点①：存入 Map
        String expr = ctx.get("expr");           // 间接节点②：从 Map 取出
        // [CHECKPOINT id=JSEF-TV-008 cwe=917 level=L5 source=userInput sink=SpelExpressionParser.parseExpression (via Map.get) expect=VULN trace=benchmark/cases/vuln/taint-variants/MapIndirectSpel.java:33,benchmark/cases/vuln/taint-variants/MapIndirectSpel.java:34,benchmark/cases/vuln/taint-variants/MapIndirectSpel.java:38]
        parseExpression(expr);                   // Map 取出值送入表达式 sink
    }

    // 抽象 sink：语义等价 SpelExpressionParser.parseExpression(expr).getValue()
    static void parseExpression(String expr) {
        System.out.println("[spel-eval] " + expr);
    }

    public static void main(String[] args) {
        new MapIndirectSpel().eval("T(java.lang.Runtime).getRuntime().exec('id')");
    }
}
