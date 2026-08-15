package com.jsef.benchmark.sec.perf;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

// 仅语义模拟：java.sql.* 为 JDK 标准 JDBC API，benchmark 样本不要求编译。
// import javax.sql.DataSource;

/**
 * JSEF-Benchmark A1「代码质量/性能 DoS」— DB 资源泄漏安全对照（SAFE）
 *
 * 安全做法：try-with-resources 自动关闭 Connection / Statement / ResultSet，
 * 无论正常返回还是异常，资源均归还连接池，避免连接池耗尽 DoS。
 * 用于计算 TN（正确不报）/ FP（误报）。
 *
 * 修复要点（对照 DbResourceLeak.java）：
 *   try-with-resources 包裹全部 JDBC 资源。
 *
 * CWE-772 / CWE-404（资源泄漏 / 不当释放）。
 */
public class DbResourceLeak_Safe {

    private Object dataSource; // 语义模拟 DataSource

    /**
     * 安全：try-with-resources 自动关闭全部 JDBC 资源。
     */
    @SuppressWarnings("unchecked")
    public void query() throws Exception {
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM orders LIMIT 100")) {
            while (rs.next()) {
                // 处理行...（演示省略）
            }
            // [CHECKPOINT id=JSEF-PERF-DB-001S cwe=772 level=L2 source=request sink=conn.createStatement expect=SAFE]
        }
    }

    private Connection getConnection() throws Exception {
        return null; // 语义占位
    }

    public static void main(String[] args) throws Exception {
        new DbResourceLeak_Safe().query();
    }
}
