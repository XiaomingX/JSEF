package com.jsef.benchmark.vuln.logging;

/**
 * JSEF Benchmark — A09 安全日志与监控失败（CWE-778，L3）
 *
 * 场景：敏感操作（如改密、转账、权限变更）完全无审计日志（audit trail）。
 *
 * 为何危险：无审计轨迹意味着无法证明"谁在何时做了什么"，既无法实时检测
 * 越权操作，也无法事后追责，属 A09 的高危缺失。
 *
 * 安全底线：仅 localhost 演示语义。
 */
public class NoAuditTrail {

    /**
     * VULN：敏感操作无审计日志。
     */
    public static void changePassword(String user, String newPwd) {
        // source：敏感操作事件
        // [CHECKPOINT id=JSEF-A09-003 cwe=778 level=L3 source=sensitive operation (password change) sink=no audit trail expect=VULN]
        storePassword(user, newPwd);   // 直接落库，无审计
    }

    private static void storePassword(String u, String p) { /* ... */ }
}
