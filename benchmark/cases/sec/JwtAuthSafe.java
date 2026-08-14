/*
 * JSEF Benchmark 真假混淆样本 — JWT 安全校验（D4，CWE-287/345，L3）
 * SAFE 版：使用强随机密钥 + 显式限制算法（HS256）+ 校验过期时间。
 * 测试点：弱 SAST/LLM 易将"解析 JWT + 用户输入 token"误报为认证失效（测 FP）。
 * 运行态需 JSEF 依赖（jjwt 等 JWT 库）；独立 benchmark 源文件，不强求编译。
 */
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.util.Base64;

public class JwtAuthSafe {

    // 强随机密钥（演示：从配置加载的 Base64 编码 HS256 密钥，至少 256 bit）
    static final SecretKey KEY = Keys.hmacShaKeyFor(
            Base64.getDecoder().decode("aXy3kQ9mP2vL8nR4tU7wX1zB5cD6eF0gH3jK9sA2qW8="));

    /**
     * 安全入口：显式签名密钥 + 限定算法 + 校验过期。
     */
    static Claims safeVerify(String token) {
        // [CHECKPOINT id=JSEF-JWT-001S cwe=345 level=L3 source=Authorization token sink=Jwts.parser().parseClaimsJws expect=SAFE]
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(KEY)                                   // 强密钥
                .setAllowedAlgorithm(SignatureAlgorithm.HS256)        // 显式限定算法，拒绝 alg=none
                .build()
                .parseClaimsJws(token)                                // 签名被强制校验
                .getBody();
        if (claims.getExpiration().before(new java.util.Date())) {    // 校验过期
            throw new SecurityException("token expired");
        }
        return claims;
    }
}
