// [VULN]  — 注意：本文件是「回归副作用」对照 sec，补丁后仍不安全（expect=VULN）
package com.jsef.benchmark.sec.patchregression;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * JSEF-Benchmark — C 类（端到端补丁回归副作用）样本 4 的对照
 * 主题：加密补丁「改用随机密钥但长度回退到 64 位 / 配置缺失降级到硬编码弱密钥」
 *       (CWE-326 不安全密钥长度 / CWE-327，难度 L4)
 *
 * 反模式（真实安全工程反模式）：
 *   开发者看到「硬编码密钥 + ECB」不安全，于是改成「运行时随机生成密钥」+ GCM。
 *   这是对的。但补丁有两个回归副作用：
 *     (1) 密钥长度从应有 128/256 位回退到 64 位（SecretKeySpec 仅取 8 字节），
 *         暴力破解成本骤降；
 *     (2) 当配置项缺失时，fallback 回退到原来的硬编码弱密钥 —— 配置缺失即降级到不安全。
 *
 * 解释漏洞（须紧跟修复方案）：
 *   残留 sink：new SecretKeySpec(keyBytes, "AES") 中 keyBytes 仅 8 字节(64 位)，
 *   且配置缺失分支 SECURE_KEY 为空时回退 HARDCODED_KEY。
 *   修复方案：密钥长度 ≥128 位；配置缺失时应 fail-closed（抛异常 / 拒绝启动），
 *   绝不 fallback 到硬编码弱密钥。
 *
 * 安全底线：仅 localhost 演示语义，不写真实利用，不生成针对真实目标的工具。
 *
 * 本 sec 文件 expect=VULN：补丁后密钥长度回退 + 弱密钥 fallback，被测工具应报。
 */
public class PatchCryptoSec {

    // 原硬编码弱密钥（本应彻底移除，却成了 fallback）
    private static final byte[] HARDCODED_KEY = "my-secret-key-123".getBytes();

    /**
     * 看似修复：随机密钥 + GCM，但密钥长度回退到 64 位，且配置缺失回退到硬编码弱密钥。
     */
    static byte[] encrypt(byte[] plaintext, String configKey) throws Exception {
        byte[] keyBytes;
        if (configKey == null || configKey.isEmpty()) {
            // 危险：配置缺失 -> 降级到硬编码弱密钥（fail-open）
            // [CHECKPOINT id=JSEF-PR-004S cwe=327 level=L4 source=missing config sink=SecretKeySpec with hardcoded fallback key expect=VULN]
            keyBytes = HARDCODED_KEY; // 不安全 fallback
        } else {
            // 危险：密钥长度回退 —— 只取前 8 字节(64 位)，远低于 128 位下限
            keyBytes = new byte[8]; // 64 位密钥，暴力可破
            new SecureRandom().nextBytes(keyBytes);
        }
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES"); // 64 位 / 硬编码弱密钥
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(plaintext);
    }
}
