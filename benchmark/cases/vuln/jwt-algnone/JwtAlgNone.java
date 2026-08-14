// [VULN]
package com.jsef.benchmark.vuln;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * JSEF-Benchmark — JWT alg:none 算法混淆 (CWE-347，难度 L2)
 *
 * 危险入口：JWT 校验时 Algorithm 由 token 头 alg 字段决定，攻击者可改
 * alg:none 并去掉签名，服务端据此用 Algorithm 的 "none" 校验通过 → 伪造身份。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实伪造 token 脚本。
 */
public class JwtAlgNone {

    /**
     * 危险：从 token 头读取 alg 决定校验算法，可被子改为 none。
     */
    static DecodedJWT verify(String token) {
        DecodedJWT jwt = JWT.decode(token);
        String alg = jwt.getAlgorithm(); // 攻击者控制：alg=none
        // [CHECKPOINT id=JSEF-JWTNONE-001 cwe=347 level=L2 source=token header alg sink=JWTVerifier.withAlgorithm(attacker-controlled) expect=VULN]
        return JWT.require(Algorithm.valueOf(alg)).build().verify(token); // alg=none 时不校验签名
    }
}
