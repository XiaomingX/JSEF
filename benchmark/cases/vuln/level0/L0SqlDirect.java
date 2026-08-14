package com.jsef.benchmark.vuln;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * JSEF-Benchmark L0 — 基线（SQL 注入，单跳直连）
 *
 * 难度：L0（基线）。source 直接传入 sink，无中间变量。
 * 用于校准 TP 基线与定位精度（CAP-03 入门级）。
 *
 * CWE-89 SQL Injection。
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class L0SqlDirect {

    /**
     * 单跳：不可信入参直接拼入 SQL 并执行（sink）。
     *
     * @param userInput 不可信输入（类比 @RequestParam username）
     */
    public void run(Connection conn, String userInput) throws Exception {
        Statement stmt = conn.createStatement();
        // [CHECKPOINT id=JSEF-L0-SQL-001 cwe=89 level=L0 source=userInput sink=Statement.executeQuery expect=VULN]
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
        while (rs.next()) { /* localhost demo */ }
    }

    public static void main(String[] args) {
        System.out.println("demo: SELECT * FROM users WHERE name = '" + "localhost-demo" + "'");
    }
}
