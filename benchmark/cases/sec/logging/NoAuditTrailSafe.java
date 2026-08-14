package com.jsef.benchmark.sec.logging;

import java.time.Instant;

/**
 * JSEF Benchmark — A09 安全对照（CWE-778，L3）
 *
 * SAFE：敏感操作落审计日志（含操作人、对象、时间）。
 */
public class NoAuditTrailSafe {

    /**
     * SAFE：敏感操作先记审计再执行。
     */
    public static void changePassword(String user, String newPwd) {
        // source：敏感操作事件
        // [CHECKPOINT id=JSEF-A09-003S cwe=778 level=L3 source=sensitive operation (password change) sink=audit trail logged expect=SAFE]
        System.out.println("[AUDIT] PASSWORD_CHANGE actor=" + user
                + " at=" + Instant.now());
        storePassword(user, newPwd);
    }

    private static void storePassword(String u, String p) { /* ... */ }
}
