/*
 * JSEF Benchmark — Phase 4 多后端注入变体
 * 样本 7：Hibernate HQL / JPA QL 字符串拼接注入（CWE-89, 难度 L3）
 *
 * 注入变体：HQL 查询字符串由用户输入直接拼接（HQL 同样可被注入，虽语法不同
 *           于原生 SQL，但同样可绕过认证/读取敏感数据）。安全写法使用命名参数
 *           :name 配合 setParameter 绑定。
 * 所需依赖（声明即可，不要求编译）：
 *   - org.hibernate.orm:hibernate-core
 *   - org.springframework.boot:spring-boot-starter-data-jpa
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.vuln;

import java.util.List;

public class HqlInjection {

    /** 模拟 JPA Query（语义占位，不强求编译）。 */
    static class Query {
        Query setParameter(String n, Object v) { return this; }
        List<?> getResultList() { return java.util.List.of(); }
    }

    /**
     * 危险入口：HQL WHERE 子句由用户输入拼接（可绕过认证）。
     * @param user 不可信用户输入（如 "admin' OR '1'='1"）
     */
    static List<?> unsafe(String user) {
        Query q = null;
        String hql = "FROM User u WHERE u.name = '" + user + "'";
        // [CHECKPOINT id=JSEF-SQL-007 cwe=89 level=L3 source=user sink=Query.getResultList(HQL concat) expect=VULN]
        return q.getResultList();
    }

    /**
     * 安全入口：使用命名参数 :name 绑定。
     */
    static List<?> safe(String user) {
        Query q = null;
        return q.setParameter("name", user).getResultList();
    }

    public static void main(String[] args) {
        System.out.println("HqlInjection demo (localhost only)");
    }
}
