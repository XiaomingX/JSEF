// [VULN]
package com.jsef.benchmark.vuln.patchregression;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * JSEF-Benchmark — C 类（端到端补丁回归副作用）样本 4
 * 主题：硬编码密钥 + ECB 模式 (CWE-327 使用 broken/risky 加密算法，难度 L4)
 *
 * 反模式：AES 使用 ECB 模式（分组独立加密，模式本身不安全），且密钥硬编码在源码中。
 *
 * 解释漏洞（须紧跟修复方案）：
 *   原代码用固定硬编码密钥 + ECB 模式，ECB 会暴露明文结构、密钥可被反编译提取。
 *   修复方案（见 sec）：应改用随机/配置派生的强密钥 + GCM 等认证加密模式，密钥长度 ≥128 位。
 *
 * 安全底线：仅 localhost 演示语义，不写真实利用，不生成针对真实目标的工具。
 */
public class PatchCryptoVuln {

    // 危险：硬编码密钥 + 仅 16 字节（128 位但 ECB 模式仍不安全）
    private static final byte[] HARDCODED_KEY = "my-secret-key-123".getBytes();

    /**
     * 危险：AES/ECB 模式 + 硬编码密钥。
     */
    static byte[] encrypt(byte[] plaintext) throws Exception {
        SecretKeySpec key = new SecretKeySpec(HARDCODED_KEY, "AES");
        // [CHECKPOINT id=JSEF-PR-004 cwe=327 level=L4 source=hardcoded key + ECB mode sink=Cipher.init AES/ECB expect=VULN]
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding"); // ECB 模式不安全
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(plaintext);
    }
}
