package com.jsef.benchmark.sec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * 语义桩：托管密钥的占位实现，替代真实 KMS 返回的 SecretKey。
 * 语义等价: kms.getSecret(alias) 返回的密钥对象。源码中不暴露任何密钥明文。
 */
class StubKmsSecretKey extends SecretKeySpec {
    StubKmsSecretKey(String alias) {
        super((alias + ":managed-rotation-v1").getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }
}

/**
 * CWE-320 密钥管理缺陷安全对照（L3）。
 *
 * 【难点/区分点】与 vuln 同构的"加载密钥 → 使用密钥"生命周期，但来源正确：
 *   1. 托管来源：密钥不再硬编码于源码常量，而是由 KMS / KeyStore 加载
 *      （语义桩声明为外部密钥服务），源码中不出现任何明文密钥。
 *   2. 版本化轮换：使用"当前活跃版本"而非单一静态密钥，支持轮换——密钥
 *      生命周期受管理，泄露可吊销、可版本切换。
 *   3. 无明文副本：签发 JWT 只用托管密钥的引用，不含任何可复制常量。
 *
 * 评分：SAFE 侧信任实现——KMS 加载与版本轮换均为真实防护。
 */
public class KeyLifecycleHardcodedSafe {

    // 语义桩：替代 AWS KMS / Java KeyStore —— 声明托管密钥加载语义。
    // 语义等价: KmsClient.encrypt(keyId="alias/token-signing") 或 KeyStore.getEntry()
    // 说明：源码中不出现密钥明文，仅存"密钥 ID/别名"。
    private static final String KEY_ALIAS = "alias/token-signing-active";

    // 语义桩：替代 Keys.hmacShaKeyFor(...) —— 声明从 KMS 取当前活跃版本密钥。
    // 语义等价: Keys.hmacShaKeyFor(kms.getSecret(KEY_ALIAS).getBytes())
    private SecretKey loadActiveKey() {
        // 密钥由托管方返回，并随轮换版本化，无源码硬编码。
        return new StubKmsSecretKey(KEY_ALIAS);
    }

    // 语义桩：替代 Jwts.builder().signWith(activeKey) —— 声明 JWT 签名语义。
    // 语义等价: Jwts.builder().signWith(activeKey).compact()
    private String signJwt(SecretKey key, String subject) {
        return "[jwt] sub=" + subject + " signed-with-kms-alias=" + key.getAlgorithm();
    }

    /**
     * 签发 JWT：密钥来自 KMS 托管加载（非源码常量），且随版本轮换。
     * checkpoint 位于"托管密钥用于 JWT 签名"的精确行。
     */
    public String issueToken(String subject) {
        SecretKey activeKey = loadActiveKey(); // 托管加载 + 版本轮换，无硬编码
        // [CHECKPOINT id=JSEF-KEY-001S cwe=320 level=L3 source=KMS KeyStore managed key alias sink=signJwt (JWT HMAC signing via KMS, versioned rotation) expect=SAFE trace=benchmark/cases/sec/KeyLifecycleHardcodedSafe.java:40]
        return signJwt(activeKey, subject);
    }
}
