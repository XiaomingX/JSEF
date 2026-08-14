/*
 * JSEF Benchmark — Phase 4 多后端注入变体（安全对照）
 * 样本 3-S：JPA createNativeQuery ? 参数（CWE-89, 难度 L3）
 *
 * 与 JpaNativeQueryInjection 配对：使用 ? 位置参数绑定，用户输入不进入 SQL
 * 文本，故 expect=SAFE。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

import java.util.List;

public class JpaNativeQueryInjectionSafe {

    static class Em {
        java.util.List<?> createNativeQuery(String sql, Object... params) { return java.util.List.of(); }
    }

    /**
     * 安全入口：? 位置参数绑定。
     */
    static List<?> safe(String role) {
        Em em = new Em();
        // [CHECKPOINT id=JSEF-SQL-003S cwe=89 level=L3 source=role sink=EntityManager.createNativeQuery(?) expect=SAFE]
        return em.createNativeQuery("SELECT * FROM users WHERE role = ?", role);
    }

    public static void main(String[] args) {
        System.out.println("JpaNativeQueryInjectionSafe demo (localhost only)");
    }
}
