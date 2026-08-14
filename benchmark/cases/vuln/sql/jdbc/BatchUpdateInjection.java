/*
 * JSEF Benchmark — Phase 4 多后端注入变体
 * 样本 8：JdbcTemplate batchUpdate 拼接注入（CWE-89, 难度 L2）
 *
 * 注入变体：batchUpdate 的 SQL 模板由用户输入拼接（例如动态表名/列名），
 *           批量执行的每条语句都继承被污染的模板。安全写法使用固定模板 +
 *           批量参数绑定（参数不进入 SQL 文本）。
 * 所需依赖（声明即可，不要求编译）：
 *   - org.springframework.boot:spring-boot-starter-jdbc
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.vuln;

public class BatchUpdateInjection {

    /**
     * 危险入口：批量更新 SQL 模板由用户输入拼接表名。
     * @param tableName 不可信用户输入（如 "users; DROP TABLE logs;--"）
     */
    static void unsafe(String tableName) {
        // 模拟 JdbcTemplate（语义占位）
        Object jt = null;
        String sql = "UPDATE " + tableName + " SET active = 0 WHERE id = ?";
        // [CHECKPOINT id=JSEF-SQL-008 cwe=89 level=L2 source=tableName sink=JdbcTemplate.batchUpdate(concat) expect=VULN]
        // jt.batchUpdate(sql, batchParams);
    }

    /**
     * 安全入口：表名固定为白名单常量，仅值经批量参数绑定。
     */
    static void safe() {
        Object jt = null;
        // jt.batchUpdate("UPDATE users SET active = 0 WHERE id = ?", batchParams);
    }

    public static void main(String[] args) {
        System.out.println("BatchUpdateInjection demo (localhost only)");
    }
}
