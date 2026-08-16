/*
 * JSEF Benchmark 样本 — JWT 弱密钥 HMAC (CWE-347, L2)
 * 使用硬编码的弱密钥（短字符串）做 HMAC 签名校验，攻击者可离线爆破。
 * 安全底线：仅 localhost 演示语义，不提供爆破脚本。
 */
package com.jsef.benchmark.vuln;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JwtWeakSecret {

    // 危险：硬编码弱密钥
    private static final String WEAK_SECRET = "secret";

    static DecodedJWT verify(String token) {
        // [CHECKPOINT id=JSEF-EXT-004 cwe=347 level=L2 source=token sink=JWTVerifier.withAlgorithm(HMAC(weak secret)) expect=VULN]
        return JWT.require(Algorithm.HMAC256(WEAK_SECRET)).build().verify(token);
    }
}
