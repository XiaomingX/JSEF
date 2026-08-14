package com.jsef.benchmark.sec;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * JSEF-Benchmark L0 — L0SqlDirect 安全对照（SAFE 混淆样本）
 *
 * 安全做法：使用 PreparedStatement 参数化查询，不可信输入作为绑定参数，
 * 不再拼入 SQL 字符串。用于计算 TN（正确不报）/ FP（误报）。
 *
 * CWE-89 SQL Injection。
 */
public class L0SqlDirectSafe {

    /**
     * 参数化查询：不可信输入仅作为占位符实参传入。
     *
     * @param userInput 不可信输入
     */
    public void run(Connection conn, String userInput) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, userInput);
        // [CHECKPOINT id=JSEF-L0-SQL-001S cwe=89 level=L0 source=userInput sink=Statement.executeQuery expect=SAFE]
        ResultSet rs = ps.executeQuery();
        while (rs.next()) { /* localhost demo */ }
    }

    public static void main(String[] args) {
        System.out.println("demo: parameterized query with localhost-demo");
    }
}
