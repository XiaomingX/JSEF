// [SAFE]
package com.jsef.benchmark.sec;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * JSEF-Benchmark — JWT alg:none 安全对照 (CWE-347，难度 L2)
 *
 * 修复：服务端硬编码预期算法（HMAC256 + 固定 secret），拒绝 none / 算法混淆，
 * token 头 alg 与期望不一致即校验失败。
 */
public class JwtAlgNoneSafe {

    private static final String SECRET = "server-hardcoded-secret";

    /**
     * 安全：硬编码 Algorithm.HMAC256，不信任 token 头 alg。
     */
    static DecodedJWT verify(String token) {
        // [CHECKPOINT id=JSEF-JWTNONE-001S cwe=347 level=L2 source=token sink=JWTVerifier.withAlgorithm(HMAC256 fixed) expect=SAFE]
        return JWT.require(Algorithm.HMAC256(SECRET)).build().verify(token);
    }
}
