package com.jsef.benchmark.vuln;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * CWE-320 密钥管理缺陷：硬编码密钥（L3 高区分度）。
 *
 * 【难点/区分点】CWE 320 当前 benchmark 为 0 样本，本样本补足。难点在"密钥
 * 生命周期"的跨节点语义：
 *   1. 密钥源缺陷：密钥明文硬编码在类常量中（源码即泄露），而非来自 KeyStore /
 *      KMS / 环境变量等托管来源。
 *   2. 使用链跨两处：密钥从"常量读取"（source）→ 用于签发 JWT/加解密（sink）。
 *      评测需识别"硬编码常量被真实用于签名/加密"，而非孤立地看到常量就报。
 *   3. 生命周期缺失：无轮换机制、无密钥版本、无托管方，密钥长期静态可预测。
 *
 * 修复：密钥经 KeyStore/KMS 加载 + 版本化轮换（见 sec 对照）。
 */
public class KeyLifecycleHardcodedVuln {

    // 硬编码密钥源：明文出现在源码常量，任何人可读取并复制出有效签名密钥。
    private static final String HMAC_SECRET = "p@ssw0rd-static-hmac-key-2024";

    // 语义桩：替代 JwtSecretKey / Keys.hmacShaKeyFor —— 声明签名语义。
    // 语义等价: Keys.hmacShaKeyFor(HMAC_SECRET.getBytes())
    private SecretKeySpec loadSigningKey() {
        return new SecretKeySpec(HMAC_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    // 语义桩：替代 Jwts.builder().signWith(secretKey) —— 声明 JWT 签名语义。
    // 语义等价: Jwts.builder().signWith(secretKey).compact()
    private String signJwt(SecretKeySpec key, String subject) {
        return "[jwt] sub=" + subject + " signed-with=" + key.getAlgorithm();
    }

    /**
     * 签发 JWT：硬编码密钥直接用于签名，无 KeyStore/KMS、无轮换。
     * checkpoint 位于"硬编码密钥用于 JWT 签名"的精确行。
     */
    public String issueToken(String subject) {
        SecretKeySpec secretKey = loadSigningKey(); // 密钥来自硬编码常量
        // [CHECKPOINT id=JSEF-KEY-001 cwe=320 level=L3 source=hardcoded HMAC_SECRET constant sink=signJwt (JWT HMAC signing with hardcoded key, no KeyStore/KMS) expect=VULN trace=benchmark/cases/vuln/KeyLifecycleHardcodedVuln.java:23]
        return signJwt(secretKey, subject);
    }
}
