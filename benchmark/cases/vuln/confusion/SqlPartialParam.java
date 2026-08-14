package com.jsef.benchmark.vuln;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * JSEF-Benchmark Phase5-A — Partial Fix（部分修复陷阱，CWE-89 SQL 注入，难度 L3）
 *
 * 混淆点（为什么容易被误判）：
 * 本方法"看似已修复"——首参数 username 使用了 PreparedStatement + 占位符（?），
 * 这是教科书式的正确做法。但后续参数（如 status / orderBy）仍用字符串拼接进入 SQL，
 * 污点并未被完全消除。弱被测对象一旦看到 PreparedStatement 就潜意识判定"安全"，
 * 从而漏报（FN）。它实际仍是 VULN。
 *
 * 目的：考察对象是否会因"表面有防护"而漏报；同时作为最难的边界样本，
 * 区分谨慎型（坚持追完整条污点链）与激进型（见占位符即收手）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class SqlPartialParam {

    /**
     * 危险入口：username 参数化，但 sortColumn 仍拼接 → 实际仍注入。
     */
    public void query(Connection conn, String username, String sortColumn) throws SQLException {
        // 仅首参数参数化 —— 看似安全
        String sql = "SELECT id, name FROM users WHERE username = ? ORDER BY " + sortColumn;
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username); // 占位符：正确
        // [CHECKPOINT id=JSEF-PF-001 cwe=89 level=L3 source=sortColumn (user-controlled) sink=Connection.prepareStatement(exec) expect=VULN]
        ps.executeQuery(); // sortColumn 直连 sink，注入仍存在
    }
}
