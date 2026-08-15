package com.jsef.benchmark.sec.perf;

import java.util.List;
import java.util.Map;

// 仅语义模拟：JdbcTemplate 为 Spring JDBC 组件，benchmark 样本不要求编译。
// import org.springframework.jdbc.core.JdbcTemplate;

/**
 * JSEF-Benchmark A1「代码质量/性能 DoS」— 慢 SQL 安全对照（SAFE）
 *
 * 安全做法：SQL 末尾追加 "LIMIT ? OFFSET ?" 并绑定分页参数，限制单次扫描行数，
 * 杜绝全表扫描造成的慢查询 / DB 资源耗尽 DoS。同时以参数化绑定避免注入。
 * 用于计算 TN（正确不报）/ FP（误报）。
 *
 * 修复要点（对照 SlowSqlNoLimit_L1/L2/L3.java）：
 *   分页 + 参数化。本 safe 样本覆盖 SQL 系列，标注 level=L1、expect=SAFE。
 *
 * CWE-89 / CWE-400（资源耗尽 / 慢查询 DoS）。
 */
public class SlowSqlNoLimit_Safe {

    private Object jdbcTemplate;

    /**
     * 安全：参数化 + 分页，限制扫描行数。
     *
     * @param keyword 不可信输入（类比 @RequestParam keyword）
     * @param limit   分页大小（受控常量/校验后参数）
     * @param offset  分页偏移
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> searchByKeyword(String keyword, int limit, int offset) {
        String sql = "SELECT * FROM orders WHERE note LIKE ? LIMIT ? OFFSET ?";
        // [CHECKPOINT id=JSEF-PERF-SQL-001S cwe=400 level=L1 source=keyword sink=jdbcTemplate.query expect=SAFE]
        return (List<Map<String, Object>>) queryForList(sql, keyword, limit, offset);
    }

    private Object queryForList(String sql, Object... args) {
        return java.util.Collections.emptyList();
    }

    public static void main(String[] args) {
        new SlowSqlNoLimit_Safe().searchByKeyword("localhost-demo", 20, 0);
    }
}
