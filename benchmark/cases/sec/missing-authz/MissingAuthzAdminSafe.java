/*
 * JSEF Benchmark 样本 — 缺失功能级访问控制安全对照 (CWE-862, L3)
 * 执行前校验角色。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

public class MissingAuthzAdminSafe {

    static String deleteUser(long targetId, String currentRole) {
        if (!"ADMIN".equals(currentRole)) { // 角色校验
            throw new SecurityException("forbidden");
        }
        // [CHECKPOINT id=JSEF-EXT-016S cwe=862 level=L3 source=authenticated request sink=role check before admin action expect=SAFE]
        return "deleted:" + targetId;
    }
}
