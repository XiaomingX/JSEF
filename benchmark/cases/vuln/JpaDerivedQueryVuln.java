package com.jsef.benchmark.vuln;

/*
 * 运行态需 JSEF 依赖：本文件引用 Spring 语义（JpaRepository 派生查询），
 * 用于静态分析 / LLM 阅读，不强求编译，但语义正确、可读。
 *
 * JSEF-Benchmark L4 — 隐式框架数据流：JPA 派生查询名注入
 *
 * 难度：L4（框架语义 / 隐式数据流）。JPA 允许通过"方法名"声明派生查询，
 * 如 findByUsername(String name) 会在运行时按方法名解析为 SQL。这里把
 * 不可信字段名拼进查询方法名：findBy + userControlledFieldName。
 * 纯语法 SAST 只看到字符串拼接，看不到 SQL；只有理解"派生查询方法名即 SQL 骨架"
 * 这一框架语义，才能识别拼接字段名导致的注入。
 *
 * CWE-89 SQL Injection。
 *
 * 安全底线：仅展示语义，Payload 仅 localhost 演示，不提供真实利用脚本。
 */
public class JpaDerivedQueryVuln {

    // 语义桩：模拟 JpaRepository 按拼接方法名执行派生查询
    // 语义等价: JpaRepository 反射解析方法名 findById/OrderBy... 并执行对应 SQL
    private static String executeDerivedQuery(String methodName, Object arg) {
        System.out.println("[derived-query] " + methodName + "(" + arg + ")"); // 语义等价: 按方法名执行 SQL
        return methodName + " -> " + arg;
    }

    /**
     * 危险入口：把不可信字段名拼进派生查询方法名，形成隐式框架数据流。
     *
     * @param userControlledFieldName 攻击者可控的字段名（如 "id; DROP TABLE"）
     */
    public String findBy(String userControlledFieldName, Object value) {
        // 不可信字段名拼接派生查询方法名（隐式框架数据流）
        String queryMethod = "findBy" + userControlledFieldName; // 语义等价: 方法名即派生查询骨架
        // [CHECKPOINT id=JSEF-JPA-001 cwe=89 level=L4 source=userControlledFieldName sink=derived query method name (SQL) expect=VULN]
        return executeDerivedQuery(queryMethod, value); // 不可信字段名进入派生查询 SQL
    }

    public static void main(String[] args) {
        System.out.println(new JpaDerivedQueryVuln().findBy("id", "1")); // localhost 演示
    }
}
