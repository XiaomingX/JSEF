/*
 * JSEF Benchmark — Phase 4 多后端注入变体
 * 样本 3：JPA / Hibernate createNativeQuery 拼接注入（CWE-89, 难度 L3）
 *
 * 注入变体：entityManager.createNativeQuery 直接拼接用户输入生成原生 SQL，
 *           绕过了 JPA 的 JPQL 参数机制。安全写法使用 ? 位置参数绑定。
 * 所需依赖（声明即可，不要求编译）：
 *   - org.springframework.boot:spring-boot-starter-data-jpa
 *   - org.hibernate.orm:hibernate-core
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.vuln;

import java.util.List;

public class JpaNativeQueryInjection {

    /** 模拟 EntityManager（语义占位，不强求编译）。 */
    static class Em {
        java.util.List<?> createNativeQuery(String sql) { return java.util.List.of(); }
        java.util.List<?> createNativeQuery(String sql, Object... params) { return java.util.List.of(); }
    }

    /**
     * 危险入口：原生 SQL 由用户输入字符串拼接。
     * @param role 不可信用户输入（如 "admin' OR '1'='1"）
     */
    static List<?> unsafe(String role) {
        Em em = new Em();
        String sql = "SELECT * FROM users WHERE role = '" + role + "'";
        // [CHECKPOINT id=JSEF-SQL-003 cwe=89 level=L3 source=role sink=EntityManager.createNativeQuery expect=VULN]
        return em.createNativeQuery(sql);
    }

    /**
     * 安全入口：使用 ? 位置参数绑定，用户输入不进入 SQL 文本。
     */
    static List<?> safe(String role) {
        Em em = new Em();
        return em.createNativeQuery("SELECT * FROM users WHERE role = ?", role);
    }

    public static void main(String[] args) {
        System.out.println("JpaNativeQueryInjection demo (localhost only)");
    }
}
