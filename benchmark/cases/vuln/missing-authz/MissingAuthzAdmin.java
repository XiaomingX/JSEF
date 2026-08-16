/*
 * JSEF Benchmark 样本 — 缺失功能级访问控制 (CWE-862, L3)
 * 管理端点无 @PreAuthorize / 角色校验，任意登录用户可调用。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

public class MissingAuthzAdmin {

    // 危险：无 @PreAuthorize("hasRole('ADMIN')")
    static String deleteUser(long targetId, String currentRole) {
        // [CHECKPOINT id=JSEF-EXT-016 cwe=862 level=L3 source=authenticated request sink=admin action without role check expect=VULN]
        return "deleted:" + targetId; // 普通用户可删任意用户
    }
}
