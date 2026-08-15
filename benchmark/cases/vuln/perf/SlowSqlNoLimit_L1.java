package com.jsef.benchmark.vuln.perf;

import java.util.List;
import java.util.Map;

// 仅语义模拟：JdbcTemplate 为 Spring JDBC 组件，benchmark 样本不要求编译。
// import org.springframework.jdbc.core.JdbcTemplate;

/**
 * JSEF-Benchmark A1「代码质量/性能 DoS」— 慢 SQL 无 LIMIT（L1 单跳）
 *
 * 长程/质量子目标清单：
 *   ① 识别不可信输入（HTTP 入参 keyword）进入 SQL 字符串拼接；
 *   ② 识别拼接后的 SQL 直接传入 JdbcTemplate.queryForList 执行；
 *   ③ 确认该查询无 LIMIT / 分页，全表扫描在大表上造成慢查询与 DB 资源耗尽（DoS）；
 *   ④ 区分「注入」与「性能 DoS」两类危害：本例聚焦 CWE-400 资源耗尽，非 SQL 注入。
 *
 * 可达性说明：
 *   source = 方法入参 keyword（类比 @RequestParam），经单行字符串拼接到达
 *   sink = jdbcTemplate.queryForList(sql)，污点单跳直连，无中间变量，L1。
 *
 * 安全底线声明：
 *   本样本仅用于 localhost 安全教学演示，Payload 仅为语义示意，不提供任何真实
 *   利用脚本、不针对真实目标发起慢查询攻击。
 *
 * 修复要点（对照 SlowSqlNoLimit_Safe.java）：
 *   在 SQL 末尾追加 "LIMIT ? OFFSET ?" 并绑定分页参数，限制单次扫描行数。
 *
 * CWE-89 / CWE-400（资源耗尽 / 慢查询 DoS）。
 */
public class SlowSqlNoLimit_L1 {

    // 语义模拟的模板（不可信源），真实场景来自 Spring 注入的 JdbcTemplate
    private Object jdbcTemplate;

    /**
     * L1 单跳：不可信 keyword 直接拼入 SELECT，无 LIMIT。
     *
     * @param keyword 不可信输入（类比 @RequestParam keyword）
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> searchByKeyword(String keyword) {
        String sql = "SELECT * FROM orders WHERE note LIKE '%" + keyword + "%'";
        // [CHECKPOINT id=JSEF-PERF-SQL-001 cwe=400 level=L1 source=keyword sink=jdbcTemplate.queryForList expect=VULN]
        return (List<Map<String, Object>>) queryForList(sql);
    }

    // 语义占位：模拟 JdbcTemplate.queryForList
    private Object queryForList(String sql) {
        return java.util.Collections.emptyList();
    }

    public static void main(String[] args) {
        new SlowSqlNoLimit_L1().searchByKeyword("localhost-demo");
    }
}
