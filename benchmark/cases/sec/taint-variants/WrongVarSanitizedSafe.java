package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L4 — WrongVarSanitized 安全对照（SAFE 混淆样本）
 *
 * 安全做法：对所有真正进入 SQL 的变量做参数化查询，被校验 / 转义的值确实
 * 送入 sink。用于计算 TN / FP。
 *
 * CWE-89 (SQL Injection)。
 */
public class WrongVarSanitizedSafe {

    public void store(String input) {
        String safe = sanitize(input);          // 校验
        // [CHECKPOINT id=JSEF-TV-004S cwe=89 level=L4 source=input sink=jdbcTemplate.update (uses sanitized value) expect=SAFE]
        jdbcUpdate(safe);                        // 送入 sink 的是被校验的 safe
    }

    static String sanitize(String s) {
        return s.replace("'", "''");
    }

    // 抽象 sink（安全）：语义等价 jdbcTemplate.update(sql)，sql 已转义
    static void jdbcUpdate(String sql) {
        System.out.println("[sql-update-safe] " + sql);
    }

    public static void main(String[] args) {
        new WrongVarSanitizedSafe().store("1'; DROP TABLE users--");
    }
}
