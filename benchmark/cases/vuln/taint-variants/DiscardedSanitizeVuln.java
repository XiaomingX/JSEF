package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L2 — 丢弃净化返回值
 *
 * 难度：L2（多跳但无断点）。sanitize() 返回新的净化字符串，但调用方未接收返回值，
 * 仍用原未净化的 name 拼接进 SQL sink。字符串不可变——原变量不变，丢弃返回值等于
 * 净化从未发生。
 *
 * CWE-89 (SQL Injection)。安全底线：仅 localhost 演示语义。
 *
 * 修复要点（对照 DiscardedSanitizeSafe.java）：使用 sanitize 返回值或参数化查询。
 *
 * 占位说明：query(sql) 仅 localhost 打印，注释声明语义等价 JDBC 拼接执行 —— 被测
 * 工具/模型应按注释声明的语义报告漏洞。
 */
public class DiscardedSanitizeVuln {

    /**
     * 拼接 SQL，净化返回值被丢弃。
     *
     * @param name 用户可控的姓名
     */
    public void lookup(String name) {
        sanitize(name);                             // 返回值被丢弃，name 未变
        // [CHECKPOINT id=JSEF-DSC-001 cwe=89 level=L2 source=user name sink=discarded sanitize return value expect=VULN]
        query("SELECT * FROM users WHERE name = '" + name + "'");
    }

    static String sanitize(String s) {
        return s.replace("'", "");
    }

    // 抽象 sink：语义等价 jdbcTemplate/Statement 拼接执行，仅 localhost 打印
    static void query(String sql) {
        System.out.println("[sql] " + sql);
    }

    public static void main(String[] args) {
        new DiscardedSanitizeVuln().lookup("x' OR '1'='1");
    }
}
