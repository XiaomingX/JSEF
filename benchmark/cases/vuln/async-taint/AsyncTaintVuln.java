package com.jsef.benchmark.vuln;

import java.util.concurrent.CompletableFuture;

/*
 * JSEF-Benchmark L3 — 异步 lambda 捕获污点隐式传播
 *
 * 难度：L3（跨方法 / 隐式传播）。不可信输入被 lambda 捕获，在 CompletableFuture
 * 异步线程中被 SpEL 求值。污点跨越线程边界与 lambda 闭包，纯语法 SAST 难以把
 * supplyAsync 内的 parseExpression 与外层 source 关联，易断链漏报。
 *
 * CWE-917 (Expression Language Injection)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 AsyncTaintSafe.java）：异步求值仅对常量表达式进行，
 * 不把不可信 tainted 送入表达式解析。
 */
public class AsyncTaint {

    /**
     * 不可信输入被 lambda 捕获，在异步任务中求值。
     *
     * @param tainted 用户可控输入
     */
    public void run(String tainted) throws Exception {
        // [CHECKPOINT id=JSEF-NV501 cwe=917 level=L3 source=tainted(lambda捕获) sink=SpEL.parseExpression (in CompletableFuture) expect=VULN]
        CompletableFuture.supplyAsync(() -> parseExpression(tainted)).get();
    }

    // 抽象 sink：语义等价 SpelExpressionParser.parseExpression(expr).getValue()
    static String parseExpression(String expr) {
        System.out.println("[spel-eval] " + expr);
        return expr;
    }

    public static void main(String[] args) throws Exception {
        new AsyncTaint().run("T(java.lang.Runtime).getRuntime().exec('id')");
    }
}
