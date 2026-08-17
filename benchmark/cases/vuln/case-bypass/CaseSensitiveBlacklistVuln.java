package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L3 — 大小写敏感黑名单绕过 SQLi
 *
 * 难度：L3（防护语义正确性）。代码用大小写敏感的黑名单（仅拦截大写 "SELECT"）
 * 校验用户输入，但攻击者用 "sElEcT" / "SeLeCt" 等混合大小写即可绕过，
 * 拼入 SQL 仍触发注入。LLM 容易把“存在关键字黑名单”误判为安全（误报 SAFE）。
 *
 * CWE-89 (SQL Injection)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 CaseSensitiveBlacklistSafe.java）：用参数化查询，
 * 或以规范化（统一大小写）后做白名单/关键字校验，而非大小写敏感黑名单。
 */
public class CaseSensitiveBlacklistVuln {

    /**
     * 大小写敏感黑名单：仅拦截 "SELECT"。
     *
     * @param userInput 用户可控输入
     */
    public void query(String userInput) {
        if (userInput.contains("SELECT")) {           // 大小写敏感：sElEcT 漏过
            throw new IllegalArgumentException("blocked");
        }
        // [CHECKPOINT id=JSEF-NV512 cwe=89 level=L3 source=userInput sink=jdbcTemplate.queryForList (case-sensitive blacklist bypass) expect=VULN trace=benchmark/cases/vuln/case-bypass/CaseSensitiveBlacklistVuln.java:25,benchmark/cases/vuln/case-bypass/CaseSensitiveBlacklistVuln.java:29]
        jdbcTemplateQuery("SELECT * FROM t WHERE name = '" + userInput + "'"); // sElEcT 绕过
    }

    // 抽象 sink：语义等价 jdbcTemplate.queryForList(sql)
    static void jdbcTemplateQuery(String sql) {
        System.out.println("[sql-exec] " + sql);
    }

    public static void main(String[] args) {
        new CaseSensitiveBlacklistVuln().query("x' sElEcT 1 FROM users --");
    }
}
