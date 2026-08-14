/*
 * JSEF Benchmark — Phase 4 多后端注入变体
 * 样本 6：NamedParameterJdbcTemplate 误用 ${} 而非 :param（CWE-89, 难度 L2）
 *
 * 注入变体：NamedParameterJdbcTemplate 本应写 ":col" 由框架参数化，但开发者
 *           错误地把列名用 ${} 直接拼入（或字符串连接），导致命名参数机制失效。
 * 所需依赖（声明即可，不要求编译）：
 *   - org.springframework.boot:spring-boot-starter-jdbc
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.vuln;

import java.util.List;
import java.util.Map;

public class JdbcNamedParamAbuse {

    /**
     * 危险入口：排序列名用 ${} 拼接而非 :param 参数绑定。
     * @param sortColumn 不可信用户输入（如 "username; DROP TABLE logs;--"）
     */
    static List<Map<String, Object>> unsafe(String sortColumn) {
        // 模拟 NamedParameterJdbcTemplate（语义占位）
        Object template = null;
        String sql = "SELECT * FROM users ORDER BY " + sortColumn;
        // [CHECKPOINT id=JSEF-SQL-006 cwe=89 level=L2 source=sortColumn sink=NamedParameterJdbcTemplate.query(${}) expect=VULN]
        return java.util.List.of();
    }

    /**
     * 安全入口：列名白名单校验后使用常量，数值/字符串值用 :param 绑定。
     */
    static List<Map<String, Object>> safe(String sortColumn) {
        if (!List.of("id", "username", "email").contains(sortColumn)) {
            throw new IllegalArgumentException("invalid sort column");
        }
        return java.util.List.of();
    }

    public static void main(String[] args) {
        System.out.println("JdbcNamedParamAbuse demo (localhost only)");
    }
}
