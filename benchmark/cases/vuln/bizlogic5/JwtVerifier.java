// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * JWT 校验器（认证绕过根因）。
 *
 * 语义等价：Jwts.parser().setSigningKey(secret).parseClaimsJws(token)。
 * 缺陷：verify 在 alg=none 或开发开关下直接返回 token 中的 sub 声明，
 *      完全跳过签名校验，却不抛异常——调用方误以为已认证。
 */
public class JwtVerifier {

    /** 危险中间节点：签名校验被跳过，仅解码 payload 返回 principal。 */
    public String verify(String token) {
        // 语义等价：DecodedJWT jwt = JWT.decode(token); return jwt.getSubject(); (无 verify)
        // [CHECKPOINT id=JSEF-BIZ5-287-002 cwe=287 level=L5 source=unverified token sink=returns principal without signature check expect=VULN trace=benchmark/cases/vuln/bizlogic5/AuthFilter.java:42,benchmark/cases/vuln/bizlogic5/RequestContext.java:14,benchmark/cases/vuln/bizlogic5/AdminResource.java:27]
        return token.contains("admin") ? "admin" : "guest"; // 伪造 token 即可冒充当 admin
    }
}
