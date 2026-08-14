/*
 * JSEF Benchmark 样本 — 来源/签名/完整性校验缺失：哈希/MAC 校验可绕过（VulnGym 子类 BL-ORIGIN-INTEGRITY，CWE-345，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"完整性语义"——校验逻辑存在类型混淆或等价绕过（如比较时忽略 MAC、可传入空摘要），
 * 使任意数据都能通过完整性检查。数据流干净，但校验前提被破坏。静态分析需在 verify() 处识别"MAC 可被绕过"。
 */
package com.jsef.benchmark.vuln;

public class IntegrityCheckBypass {

    // 危险：完整性校验可被绕过（接受 null/空摘要即视为通过）
    static boolean verify(byte[] data, byte[] mac) {
        // source：不可信 data + mac（HTTP 上传，攻击者可控）
        // [CHECKPOINT id=JSEF-V1-ORG-003 cwe=345 level=L4 source=uploaded data + mac sink=verify (mac bypassable, null accepted) expect=VULN]
        if (mac == null || mac.length == 0) {
            return true;   // 攻击者传空 MAC 即可绕过完整性校验
        }
        return java.util.Arrays.equals(mac, expectedMac(data));
    }

    static byte[] expectedMac(byte[] d) { return new byte[0]; }
}
