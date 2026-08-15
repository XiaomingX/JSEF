package com.jsef.benchmark.vuln.perf;

import java.util.List;
import java.util.Map;

// 仅语义模拟：JdbcTemplate 为 Spring JDBC 组件，benchmark 样本不要求编译。
// import org.springframework.jdbc.core.JdbcTemplate;

/**
 * JSEF-Benchmark A1「代码质量/性能 DoS」— 慢 SQL 无 LIMIT（L2 多跳）
 *
 * 长程/质量子目标清单：
 *   ① 识别不可信输入 status / keyword 进入条件片段拼接；
 *   ② 识别经中间变量 whereClause 累积后拼成完整 SQL；
 *   ③ 确认最终 SQL 仍无 LIMIT / 分页，多条件组合扫描全表导致慢查询 DoS；
 *   ④ 区分 CWE-400（资源耗尽）与 CWE-89（注入）两类危害视角。
 *
 * 可达性说明：
 *   source = status、keyword（方法入参），经中间变量 whereClause 拼接后到达
 *   sink = jdbcTemplate.queryForList(sql)，≥2 个中间变量/步骤，L2。
 *
 * 安全底线声明：
 *   仅 localhost 教学演示，Payload 为语义示意，不提供真实利用脚本，不针对
 *   真实目标发起慢查询攻击。
 *
 * 修复要点（对照 SlowSqlNoLimit_Safe.java）：
 *   追加 "LIMIT ? OFFSET ?" 分页，并将条件用参数化绑定。
 *
 * CWE-89 / CWE-400（资源耗尽 / 慢查询 DoS）。
 */
public class SlowSqlNoLimit_L2 {

    private Object jdbcTemplate;

    /**
     * L2 多跳：多个不可信入参经中间变量 whereClause 拼接后拼入 SELECT，无 LIMIT。
     *
     * @param status  不可信输入（类比 @RequestParam status）
     * @param keyword 不可信输入（类比 @RequestParam keyword）
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> search(String status, String keyword) {
        StringBuilder whereClause = new StringBuilder(" WHERE 1=1");
        whereClause.append(" AND status = '").append(status).append("'");
        whereClause.append(" AND note LIKE '%").append(keyword).append("%'");
        String sql = "SELECT * FROM orders" + whereClause.toString();
        // [CHECKPOINT id=JSEF-PERF-SQL-002 cwe=400 level=L2 source=status,keyword sink=jdbcTemplate.queryForList expect=VULN]
        return (List<Map<String, Object>>) queryForList(sql);
    }

    private Object queryForList(String sql) {
        return java.util.Collections.emptyList();
    }

    public static void main(String[] args) {
        new SlowSqlNoLimit_L2().search("active", "localhost-demo");
    }
}
