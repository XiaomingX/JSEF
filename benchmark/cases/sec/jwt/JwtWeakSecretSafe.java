/*
 * JSEF Benchmark 样本 — JWT 弱密钥 HMAC 安全对照 (CWE-347, L2)
 * 使用由安全随机源生成的强密钥，并校验长度。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.security.SecureRandom;

public class JwtWeakSecretSafe {

    // 强密钥：由安全随机源生成（演示用长度足够的字节）
    private static final byte[] STRONG_SECRET = new byte[32];
    static {
        new SecureRandom().nextBytes(STRONG_SECRET);
    }

    static DecodedJWT verify(String token) {
        // [CHECKPOINT id=JSEF-EXT-004S cwe=347 level=L2 source=token sink=JWTVerifier.withAlgorithm(HMAC(strong random key)) expect=SAFE]
        return JWT.require(Algorithm.HMAC256(STRONG_SECRET)).build().verify(token);
    }
}
