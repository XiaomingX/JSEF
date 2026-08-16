/*
 * JSEF Benchmark 样本 — 弱加密/弱哈希安全对照 (CWE-327/328, L2)
 * 使用 AES-GCM 加密、BCrypt 哈希口令。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class WeakCryptoSafe {

    static byte[] encrypt(byte[] key, byte[] data) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        SecretKeySpec ks = new SecretKeySpec(key, "AES");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, ks, new GCMParameterSpec(128, iv));
        // [CHECKPOINT id=JSEF-EXT-011S cwe=327 level=L2 source=data sink=Cipher(AES/GCM) doFinal expect=SAFE]
        return c.doFinal(data);
    }

    // 演示：用 SHA-256 + 盐做强哈希（生产建议 BCrypt/Argon2）
    static byte[] hashPassword(String password, byte[] salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        // [CHECKPOINT id=JSEF-EXT-012S cwe=328 level=L2 source=password sink=MessageDigest(SHA-256)+salt digest expect=SAFE]
        return md.digest(password.getBytes());
    }
}
