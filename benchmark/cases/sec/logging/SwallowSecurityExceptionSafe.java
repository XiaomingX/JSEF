package com.jsef.benchmark.sec.logging;

import java.time.Instant;

/**
 * JSEF Benchmark — A09 安全对照（CWE-390，L2）
 *
 * SAFE：捕获安全异常后记录日志并按策略处置（如告警/拒绝）。
 */
public class SwallowSecurityExceptionSafe {

    /**
     * SAFE：捕获安全异常后记录并处置。
     */
    public static boolean verifySignature(byte[] payload, byte[] sig) {
        try {
            return doVerify(payload, sig);
        } catch (SecurityException e) {
            // source：被捕获的安全异常
            // [CHECKPOINT id=JSEF-A09-004S cwe=390 level=L2 source=security exception (catch) sink=log + handle/alert expect=SAFE]
            System.out.println("[AUDIT] SIGNATURE_VERIFY_FAIL at=" + Instant.now()
                    + " reason=" + e.getMessage());
            return false;   // 记录后再拒绝
        }
    }

    private static boolean doVerify(byte[] p, byte[] s) { return true; }
}
