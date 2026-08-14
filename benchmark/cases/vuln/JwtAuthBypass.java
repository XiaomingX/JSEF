/*
 * JSEF Benchmark 样本 — JWT 认证失效（D4，CWE-287/345，L2/L3）
 * 运行态需 JSEF 依赖（jjwt 等 JWT 库）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实越权利用。
 */
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;

public class JwtAuthBypass {

    // 危险：硬编码弱密钥
    static final String SECRET = "secret";

    /**
     * 危险入口：解析 JWT 但未校验签名（忽略签名 / alg=none 可被接受）。
     */
    static Claims verify(String token) {
        // source：不可信 token（HTTP Authorization 头）
        // [CHECKPOINT id=JSEF-JWT-001 cwe=345 level=L3 source=Authorization token sink=Jwts.parser().parseClaimsJwt expect=VULN]
        // parser 未 setSigningKey / 未限制算法：签名被忽略，alg=none 可被伪造
        Claims claims = Jwts.parser()
                .parseClaimsJwt(token)   // 未校验签名 → 认证失效
                .getBody();
        return claims;
    }
}
