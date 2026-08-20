package com.jsef.benchmark.sec;

/**
 * JSEF-Benchmark L4 — JPA 派生查询安全对照（SAFE）
 *
 * 安全做法：查询字段名不取自不可信输入，而是经白名单/常量映射。
 * 这里用 switch 把不可信输入固定映射到白名单常量字段名（username/id/email），
 * 其余输入一律拒绝。拼接进派生查询方法名的是常量，污点不可达 SQL。
 *
 * CWE-89 SQL Injection。
 */
public class JpaDerivedQuerySafe {

    private static final String FIELD_USERNAME = "Username";
    private static final String FIELD_ID = "Id";
    private static final String FIELD_EMAIL = "Email";

    // 语义桩：模拟 JpaRepository 派生查询执行（SAFE 侧按实现判定为安全）
    private static String executeDerivedQuery(String methodName, Object arg) {
        return methodName + " -> " + arg;
    }

    /**
     * 安全入口：字段名经白名单映射，绝不使用不可信原始输入拼接方法名。
     *
     * @param field 攻击者可控的字段名选择
     */
    public String findBySafe(String field, Object value) {
        // 白名单映射：仅允许固定字段名，其余抛异常
        String mapped;
        switch (field) {
            case "username": mapped = FIELD_USERNAME; break;
            case "id":       mapped = FIELD_ID;       break;
            case "email":    mapped = FIELD_EMAIL;    break;
            default:
                throw new IllegalArgumentException("unsupported field: " + field);
        }
        String queryMethod = "findBy" + mapped; // 拼接的是白名单常量，污点已被阻断
        // [CHECKPOINT id=JSEF-JPA-001S cwe=89 level=L4 source=field sink=derived query method name (SQL) expect=SAFE]
        return executeDerivedQuery(queryMethod, value); // 方法名来自常量映射，不可达注入
    }

    public static void main(String[] args) {
        System.out.println(new JpaDerivedQuerySafe().findBySafe("id", "1")); // localhost 演示
    }
}
