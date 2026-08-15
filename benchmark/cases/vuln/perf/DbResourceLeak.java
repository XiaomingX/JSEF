package com.jsef.benchmark.vuln.perf;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

// 仅语义模拟：java.sql.* 为 JDK 标准 JDBC API，benchmark 样本不要求编译。
// import javax.sql.DataSource;

/**
 * JSEF-Benchmark A1「代码质量/性能 DoS」— DB 资源泄漏（L2 多跳）
 *
 * 长程/质量子目标清单：
 *   ① 识别从 DataSource 获取 Connection 后手动创建 Statement/ResultSet；
 *   ② 识别异常路径下 finally 缺失或关闭顺序错误，导致连接未归还连接池；
 *   ③ 识别在循环 / 高并发调用中复用该缺陷，连接池耗尽 → DB DoS；
 *   ④ 区分 CWE-772（资源未关闭）与 CWE-404（资源不当释放）语义。
 *
 * 可达性说明：
 *   source = 外部请求触发的 query() 调用（类比 Controller 入口），经
 *   conn.createStatement() → stmt.executeQuery() 多步到达资源占用点，
 *   L2（≥2 个中间资源对象，且存在异常分支导致泄漏）。
 *
 * 安全底线声明：
 *   仅 localhost 教学演示，不提供真实连接池耗尽攻击脚本，不针对真实数据库。
 *
 * 修复要点（对照 DbResourceLeak_Safe.java）：
 *   使用 try-with-resources 自动关闭 Connection / Statement / ResultSet。
 *
 * CWE-772 / CWE-404（资源泄漏 / 不当释放）。
 */
public class DbResourceLeak {

    private Object dataSource; // 语义模拟 DataSource

    /**
     * 手动获取连接与语句，未在 finally 中关闭，异常时泄漏。
     */
    @SuppressWarnings("unchecked")
    public void query() throws Exception {
        Connection conn = getConnection(); // 语义模拟：从池获取
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM orders");
        while (rs.next()) {
            // 处理行...（演示省略）
        }
        // [CHECKPOINT id=JSEF-PERF-DB-001 cwe=772 level=L2 source=request sink=conn.createStatement expect=VULN]
        // 缺陷：conn/stmt/rs 均未关闭，异常时直接泄漏，连接池耗尽导致 DoS
    }

    private Connection getConnection() throws Exception {
        return null; // 语义占位
    }

    public static void main(String[] args) throws Exception {
        new DbResourceLeak().query();
    }
}
