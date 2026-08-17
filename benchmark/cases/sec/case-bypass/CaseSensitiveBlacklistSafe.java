package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L3 — CaseSensitiveBlacklist 安全对照（SAFE 混淆样本）
 *
 * 安全做法：对输入统一大小写后做关键字拒绝（或直接使用参数化查询），
 * 混合大小写无法绕过。用于计算 TN / FP。
 *
 * CWE-89 (SQL Injection)。
 */
public class CaseSensitiveBlacklistSafe {

    public void query(String userInput) {
        if (userInput.toUpperCase().contains("SELECT")) {  // 规范化后校验，无法绕过
            throw new IllegalArgumentException("blocked");
        }
        // [CHECKPOINT id=JSEF-NV512S cwe=89 level=L3 source=userInput sink=jdbcTemplate.queryForList (normalized keyword check) expect=SAFE]
        jdbcTemplateQueryParam("SELECT * FROM t WHERE name = ?", userInput); // 参数化
    }

    // 抽象 sink（安全）：语义等价 jdbcTemplate.queryForList(sql, param)
    static void jdbcTemplateQueryParam(String sql, String param) {
        System.out.println("[sql-exec-safe] " + sql + " param=" + param);
    }

    public static void main(String[] args) {
        new CaseSensitiveBlacklistSafe().query("x' sElEcT 1 FROM users --");
    }
}
