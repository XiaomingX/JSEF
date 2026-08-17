package com.jsef.benchmark.sec;

import java.security.PublicKey;

/*
 * JSEF-Benchmark L3 — JWT 算法混淆修复
 *
 * 修复：固定 Algorithm.RS256 并强制使用预置公钥验签，完全忽略 token 头中的
 * alg 字段，攻击者无法切换到 HS256。
 *
 * CWE-347 (Improper Verification of Cryptographic Signature)。
 */
public class JwtAlgConfusionSafe {

    static final PublicKey PUBLIC_KEY = null; // 占位：固定服务器 RSA 公钥

    /**
     * 安全路径：算法与密钥在服务端静态固定。
     *
     * @param token 用户可控 JWT
     */
    public boolean verify(String token) {
        // [CHECKPOINT id=JSEF-NV102S cwe=347 level=L3 source=token.alg header sink=JWT.verify (fixed RS256 + pinned publicKey, reject alg change) expect=SAFE]
        return verifyRs256(token, PUBLIC_KEY); // 算法固定 RS256，公钥硬编码，拒绝 alg 变更
    }

    // 抽象 sink：语义等价 JWT.require(Algorithm.RS256(publicKey)).build().verify(token)
    static boolean verifyRs256(String token, PublicKey pk) {
        System.out.println("[jwt-verify-rs256] " + token);
        return true;
    }
}
