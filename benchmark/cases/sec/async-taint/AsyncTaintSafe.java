package com.jsef.benchmark.sec;

import java.util.concurrent.CompletableFuture;

/*
 * JSEF-Benchmark L3 — 异步 lambda 安全对照
 *
 * 修复：异步任务内仅对常量表达式求值，不可信 tainted 不进入 parseExpression。
 * SAFE 侧按实现判定安全。
 */
public class AsyncTaintSafe {

    public void run(String tainted) throws Exception {
        // [CHECKPOINT id=JSEF-NV501S cwe=917 level=L3 source=tainted(lambda捕获) sink=SpEL.parseExpression (in CompletableFuture) expect=SAFE]
        CompletableFuture.supplyAsync(() -> parseExpression("${sec.constant}")).get();
    }

    // 抽象 sink：语义等价 SpelExpressionParser.parseExpression(expr).getValue()
    static String parseExpression(String expr) {
        System.out.println("[spel-eval] " + expr);
        return expr;
    }

    public static void main(String[] args) throws Exception {
        new AsyncTaintSafe().run("T(java.lang.Runtime).getRuntime().exec('id')");
    }
}
