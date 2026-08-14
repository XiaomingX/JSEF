package com.jsef.benchmark.sec;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Set;

/**
 * JSEF-Benchmark Phase5-A — Partial Fix 的真正修复版（CWE-89 SQL 注入，难度 L3）
 *
 * 与 SqlPartialParam 对照：本方法对所有参数都做了安全处理——
 * 1) 绑定值（username）用占位符；
 * 2) 结构性片段（排序列）走白名单枚举，不接受任意用户输入。
 * 因此是真正的 SAFE，用于计算 TN / 误报（FP）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class SqlPartialParamSafe {

    // 仅允许排序的列白名单（受控常量）
    static final Set<String> ALLOWED_COLUMNS = Set.of("id", "name", "created_at");

    /**
     * 安全入口：绑定值用占位符，结构片段走白名单。
     */
    public void query(Connection conn, String username, String sortColumn) throws SQLException {
        if (!ALLOWED_COLUMNS.contains(sortColumn)) {
            throw new IllegalArgumentException("invalid sort column");
        }
        String sql = "SELECT id, name FROM users WHERE username = ? ORDER BY " + sortColumn;
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username);
        // [CHECKPOINT id=JSEF-PF-001S cwe=89 level=L3 source=sortColumn (whitelist-checked) sink=Connection.prepareStatement(exec) expect=SAFE]
        ps.executeQuery(); // 已全参数化 / 白名单，无注入
    }
}
