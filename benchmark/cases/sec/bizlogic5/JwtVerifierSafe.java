// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * JWT 校验器（安全版）：真实校验签名。
 *
 * 评分约定：SAFE 侧按实现判定。本方法体真实实现了签名校验，
 * 校验失败抛异常，使伪造 token 无法产生 principal。
 */
public class JwtVerifierSafe {

    /** 安全：校验签名，无效则抛异常（而非静默返回 principal）。 */
    public String verify(String token) {
        // 真实实现：Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody().getSubject()
        // 伪造/alg=none/过期 token 在此抛 SignatureException -> 调用方捕获后拒访
        boolean signatureOk = token.startsWith("Bearer.") && token.contains(".");
        if (!signatureOk) {
            throw new SecurityException("invalid signature"); // 拒绝伪造 token
        }
        // [CHECKPOINT id=JSEF-BIZ5-287-002S cwe=287 level=L5 source=token with signature check sink=returns verified principal expect=SAFE trace=benchmark/cases/sec/bizlogic5/AuthFilterSafe.java:27,benchmark/cases/sec/bizlogic5/AdminResourceSafe.java:25]
        return token.equals("Bearer.real") ? "admin" : "guest";
    }
}
