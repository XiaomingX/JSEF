package com.jsef.benchmark.sec;

import java.util.concurrent.CompletableFuture;

/*
 * 运行态需 JSEF 依赖：使用标准 java.util.concurrent.CompletableFuture 语义，
 * 用于静态分析 / LLM 阅读，不强求编译，但语义正确、可读。
 *
 * JSEF-Benchmark L4 — 跨集合/异步传播长链（SAFE 对照，CWE-89）
 *
 * 同链安全对照：vuln 侧不可信输入经 CompletableFuture 三级异步链传播后拼入 SQL 串
 * （jdbcTemplate.queryForList）。本 SAFE 侧同样经历多级异步链（supplyAsync -> thenApply
 * -> thenCompose -> thenApply），但**末端用参数化查询**：不可信值作为绑定参数传入
 * PreparedStatement，绝不拼入 SQL 语句本身。
 *
 * 难点/区分点：
 *   - 与 vuln 侧**同样的多级异步传播结构**，仅末端 sink 处理方式不同（拼接 vs 参数化）。
 *   - 用于检验工具能否识别"末端参数化/PreparedStatement"这一净化点，从而对同类异步链
 *     正确判 SAFE，而非因看到 CompletableFuture 链 + SQL 就一律报注入。
 *
 * CWE-89 (SQL Injection)。判 SAFE：不可信值进入绑定参数，非拼接。
 */
public class AsyncChainSqlSafe {

    /**
     * 安全入口：不可信输入经多级异步链传播，但末端参数化查询。
     *
     * @param userId 不可信输入（如 HTTP 参数）
     */
    public void run(String userId) throws Exception {
        // 阶段① supplyAsync：不可信输入进入异步链
        CompletableFuture<String> stage1 = CompletableFuture.supplyAsync(() -> userId);
        // 阶段② thenApply：处理①
        CompletableFuture<String> stage2 = stage1.thenApply(v -> "prefix:" + v);
        // 阶段③ thenCompose：处理②
        CompletableFuture<String> stage3 = stage2.thenCompose(v ->
                CompletableFuture.completedFuture(v.substring(0, v.length())));
        // 阶段④ thenApply：仅取参数值，不做 SQL 拼接
        CompletableFuture<String> stage4 = stage3.thenApply(v -> v);
        // [CHECKPOINT id=JSEF-ASYNCCHAIN-001S cwe=89 level=L4 source=userId sink=jdbcTemplate.query(parameterized) expect=SAFE]
        // 末端参数化查询：不可信值作为绑定参数，不拼入 SQL 语句
        queryParameterized("SELECT * FROM t WHERE uid=?", stage4.get());
    }

    // 语义桩：SAFE 侧真实实现参数化查询（PreparedStatement 绑定参数）
    private static void queryParameterized(String sql, Object param) {
        // 语义等价: jdbcTemplate.query(sql, ps -> ps.setString(1, (String) param), ...)
        System.out.println("[sql-param] " + sql + " -> " + param); // 参数绑定，非拼接
    }

    public static void main(String[] args) throws Exception {
        new AsyncChainSqlSafe().run("1' OR '1'='1"); // 仅 localhost 演示语义，参数化后无注入
    }
}
