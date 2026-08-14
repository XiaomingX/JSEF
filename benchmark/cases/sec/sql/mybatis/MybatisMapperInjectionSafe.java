/*
 * JSEF Benchmark — Phase 4 多后端注入变体（安全对照）
 * 样本 1-S：MyBatis Mapper #{} 参数化（CWE-89, 难度 L2）
 *
 * 与 MybatisMapperInjection 配对：此处排序字段使用 #{} 预编译参数 + 白名单，
 * 用户输入不会进入 SQL 文本，故 expect=SAFE。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

import java.util.List;
import java.util.Map;

public class MybatisMapperInjectionSafe {

    public interface UserMapper {
        List<Map<String, Object>> findByOrderSafe(String orderBy);
    }

    /**
     * 安全入口：#{} 参数化 + 白名单校验。
     */
    static List<Map<String, Object>> safe(String orderBy) {
        UserMapper mapper = null;
        if (!List.of("id", "username", "email").contains(orderBy)) {
            throw new IllegalArgumentException("invalid order column");
        }
        // #{} 由 MyBatis 转为 PreparedStatement 参数
        // [CHECKPOINT id=JSEF-SQL-001S cwe=89 level=L2 source=orderBy sink=UserMapper.findByOrderSafe(#{}) expect=SAFE]
        return mapper.findByOrderSafe(orderBy);
    }

    public static void main(String[] args) {
        System.out.println("MybatisMapperInjectionSafe demo (localhost only)");
    }
}
