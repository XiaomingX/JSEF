package com.jsef.benchmark.vuln.logging;

/**
 * JSEF Benchmark — A09 安全日志与监控失败（CWE-390，L2）
 *
 * 场景：捕获到安全相关异常（如鉴权失败、签名校验失败）后直接吞掉，
 * 既不记录也不向上传递，使攻击被静默掩盖。
 *
 * 为何危险：吞掉安全异常等于关闭了该事件的监控，攻击者可借此反复探测
 * 而毫无痕迹，是 A09 中典型的"监控失败"。
 *
 * 安全底线：仅 localhost 演示语义。
 */
public class SwallowSecurityException {

    /**
     * VULN：捕获安全异常后吞掉，不记录不处置。
     */
    public static boolean verifySignature(byte[] payload, byte[] sig) {
        try {
            return doVerify(payload, sig);
        } catch (SecurityException e) {
            // source：被捕获的安全异常
            // [CHECKPOINT id=JSEF-A09-004 cwe=390 level=L2 source=security exception (catch) sink=swallowed (no log/handle) expect=VULN]
            return false;   // 静默吞掉，无日志
        }
    }

    private static boolean doVerify(byte[] p, byte[] s) { return true; }
}
