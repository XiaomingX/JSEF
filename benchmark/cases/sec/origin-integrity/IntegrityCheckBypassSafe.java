/*
 * JSEF Benchmark 样本 — 来源/签名/完整性校验缺失：MAC 严格校验（safe 对照，CWE-345，L4）
 * 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

public class IntegrityCheckBypassSafe {

    // 安全：MAC 必须存在且恒定时间比较相等
    static boolean verify(byte[] data, byte[] mac) {
        // [CHECKPOINT id=JSEF-V1-ORG-003S cwe=345 level=L4 source=uploaded data + mac sink=verify (mac required, constant-time) expect=SAFE]
        if (mac == null || mac.length == 0) return false;
        byte[] exp = expectedMac(data);
        if (mac.length != exp.length) return false;
        int result = 0;
        for (int i = 0; i < exp.length; i++) {
            result |= mac[i] ^ exp[i];
        }
        return result == 0;
    }

    static byte[] expectedMac(byte[] d) { return new byte[0]; }
}
