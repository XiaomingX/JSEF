package com.jsef.benchmark.vuln;

import java.util.concurrent.CompletableFuture;

/*
 * 运行态需 JSEF 依赖：使用标准 java.util.concurrent.CompletableFuture 语义，
 * 用于静态分析 / LLM 阅读，不强求编译，但语义正确、可读。危险 sink 为语义桩。
 *
 * JSEF-Benchmark L4 — 跨集合/异步传播长链（SQL 注入，CWE-89）
 *
 * 难度：L4（跨方法 + 多级异步传播）。不可信输入经 CompletableFuture 三级链式异步
 * 传播后进入 SQL 拼接 sink：
 *   supplyAsync(源) -> thenApply(处理①) -> thenCompose(处理②) -> thenApply(组装SQL) -> 查询
 *
 * 难点/区分点（相对现有 async-taint 单层 lambda）：
 *   - 现有 async-taint 是**单层** supplyAsync 内一个 lambda 捕获污点直接求值（L3）。
 *   - 本样本是**多级链式异步**：污点逐级经过 thenApply -> thenCompose -> thenApply，
 *     每一级的回调都在不同 CompletableFuture 阶段执行。纯语法 SAST 需跨多个
 *     CompletableFuture 回调边界做数据流追踪，才能从 source 一路追到 SQL 拼接 sink；
 *     跨异步阶段传播容易断链漏报。
 *   - 且每个阶段有"看似正常的业务处理"（拼前缀 / 过滤空格），单独看都不像危险操作，
 *     组合起来才是把不可信值拼入 SQL。
 *
 * CWE-89 (SQL Injection)。
 * 安全底线：仅展示语义，不提供真实注入载荷。
 */
public class AsyncChainSqlVuln {

    /**
     * 危险入口：不可信输入经三级 CompletableFuture 异步链传播后进入 SQL 拼接 sink。
     *
     * @param userId 不可信输入（如 HTTP 参数）
     */
    public void run(String userId) throws Exception {
        // 阶段① supplyAsync：不可信输入进入异步链（source）
        CompletableFuture<String> stage1 = CompletableFuture.supplyAsync(() -> userId);
        // 阶段② thenApply：处理① —— 仅加前缀，看似正常
        CompletableFuture<String> stage2 = stage1.thenApply(v -> "prefix:" + v);
        // 阶段③ thenCompose：处理② —— 取子串，仍携带污点
        CompletableFuture<String> stage3 = stage2.thenCompose(v ->
                CompletableFuture.completedFuture(v.substring(0, v.length())));
        // 阶段④ thenApply：组装 SQL（污点到达 sink 的中间节点）
        CompletableFuture<String> stage4 = stage3.thenApply(v -> "SELECT * FROM t WHERE uid='" + v + "'");
        // [CHECKPOINT id=JSEF-ASYNCCHAIN-001 cwe=89 level=L4 source=userId sink=jdbcTemplate.queryForList expect=VULN trace=benchmark/cases/vuln/AsyncChainSqlVuln.java:36,benchmark/cases/vuln/AsyncChainSqlVuln.java:38,benchmark/cases/vuln/AsyncChainSqlVuln.java:40,benchmark/cases/vuln/AsyncChainSqlVuln.java:43]
        queryForList(stage4.get()); // 语义等价: jdbcTemplate.queryForList(sql, new Object[]{})
    }

    // 语义桩：VULN 侧信方法名/注释声明（AGENTS.md 抽象桩约定）
    private static void queryForList(String sql) {
        System.out.println("[sql-query] " + sql); // 语义等价: jdbcTemplate.queryForList(sql, new Object[]{})
    }

    public static void main(String[] args) throws Exception {
        new AsyncChainSqlVuln().run("1' OR '1'='1"); // 仅 localhost 演示语义，非真实攻击
    }
}
