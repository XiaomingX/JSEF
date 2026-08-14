/*
 * JSEF Benchmark — Phase 4 多后端注入变体（安全对照）
 * 样本 2-S：MyBatis @Select 白名单表名（CWE-89, 难度 L3）
 *
 * 与 MybatisAnnotationInjection 配对：表名经白名单校验后使用常量，用户输入
 * 被拒绝进入 SQL 文本，故 expect=SAFE。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

import java.util.List;
import java.util.Map;

public class MybatisAnnotationInjectionSafe {

    public interface ReportMapper {
        List<Map<String, Object>> selectByTableSafe(String tableName);
    }

    /**
     * 安全入口：表名白名单常量。
     */
    static List<Map<String, Object>> safe(String tableName) {
        ReportMapper mapper = null;
        if (!List.of("users", "orders", "logs").contains(tableName)) {
            throw new IllegalArgumentException("invalid table");
        }
        // [CHECKPOINT id=JSEF-SQL-002S cwe=89 level=L3 source=tableName sink=@Select(#{} whitelist) expect=SAFE]
        return mapper.selectByTableSafe(tableName);
    }

    public static void main(String[] args) {
        System.out.println("MybatisAnnotationInjectionSafe demo (localhost only)");
    }
}
