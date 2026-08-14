package com.jsef.benchmark.vendor;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * JSEF-Benchmark B6 — OWASP 式真/假漏洞混淆（SQL 注入 CWE-89）
 *
 * 抽象自 OWASP Benchmark（https://github.com/OWASP-Benchmark/BenchmarkJava）。
 * 该 benchmark 以 BenchmarkTestXXXXX 命名，提供真/假漏洞配对（TP/FN/FP/TN），
 * 用于 Youden Score 口径的 SAST 能力验收（CAP-11 误报抑制）。
 *
 * 本文件提供一对紧邻方法：一个用字符串拼接 SQL（VULN），一个用 PreparedStatement（SAFE）。
 * 难度：L1（单跳混淆）。两个 checkpoint 行内标注见下。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 * 引用框架类说明：本样本为自包含 Java 源码，仅演示 JDBC 原生 API，不依赖 JSEF src/main。
 */
public class OwaspStyle_SQLi_Confusion {

    /**
     * VULN：用字符串拼接构造 SQL，用户输入直接进入查询（sink）。
     * 对应 OWASP Benchmark 的 BenchmarkTestXXXXX（真漏洞）风格。
     */
    public void unsafeQuery(Connection conn, String userInput) throws SQLException {
        Statement stmt = conn.createStatement();
        // [CHECKPOINT id=JSEF-VEND-SQL-001 cwe=89 level=L1 source=userInput sink=Statement.executeQuery expect=VULN]
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
        rs.close();
    }

    /**
     * SAFE：使用 PreparedStatement + 占位符，用户输入不会破坏 SQL 结构（混淆样本，不应报）。
     * 对应 OWASP Benchmark 的 good 变体风格。
     */
    public void safeQuery(Connection conn, String userInput) throws SQLException {
        // [CHECKPOINT id=JSEF-VEND-SQL-001S cwe=89 level=L1 source=userInput sink=PreparedStatement.executeQuery expect=SAFE]
        java.sql.PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, userInput);
        ResultSet rs = ps.executeQuery();
        rs.close();
    }
}
