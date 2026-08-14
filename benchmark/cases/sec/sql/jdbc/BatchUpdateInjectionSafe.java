/*
 * JSEF Benchmark — Phase 4 多后端注入变体（安全对照）
 * 样本 8-S：JdbcTemplate batchUpdate 固定模板（CWE-89, 难度 L2）
 *
 * 与 BatchUpdateInjection 配对：SQL 模板固定为白名单常量，仅值经批量参数
 * 绑定，用户输入不进入 SQL 文本，故 expect=SAFE。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

public class BatchUpdateInjectionSafe {

    /**
     * 安全入口：固定表名模板 + 批量参数绑定。
     */
    static void safe() {
        Object jt = null;
        // [CHECKPOINT id=JSEF-SQL-008S cwe=89 level=L2 source=(none) sink=JdbcTemplate.batchUpdate(fixed) expect=SAFE]
        // jt.batchUpdate("UPDATE users SET active = 0 WHERE id = ?", batchParams);
    }

    public static void main(String[] args) {
        System.out.println("BatchUpdateInjectionSafe demo (localhost only)");
    }
}
