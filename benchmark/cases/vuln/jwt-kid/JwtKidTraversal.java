// [VULN]
package com.jsef.benchmark.vuln;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.JWT;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.FileInputStream;

/**
 * JSEF-Benchmark — JWT kid 路径遍历 (CWE-22，难度 L3)
 *
 * 危险入口：JWT 校验用 kid 头字段直接拼文件路径加载密钥文件
 * （new FileInputStream(kid) 或 Files.readAllBytes(Paths.get(kid))），
 * 未校验 kid → 攻击者可传 kid=../../../../etc/passwd 读取任意文件。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实任意文件读取脚本。
 */
public class JwtKidTraversal {

    /**
     * 危险：kid 直接作为文件路径，未校验 → 路径遍历。
     */
    static java.security.PrivateKey loadKey(DecodedJWT jwt) throws Exception {
        String kid = jwt.getHeaderClaim("kid").asString(); // 攻击者控制
        // [CHECKPOINT id=JSEF-JWTKID-001 cwe=22 level=L3 source=kid header claim sink=Files.readAllBytes(Paths.get(kid)) expect=VULN]
        byte[] keyBytes = Files.readAllBytes(Paths.get(kid)); // 可读取任意文件
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    /**
     * 危险变体：用 FileInputStream 直接拼 kid。
     */
    static byte[] loadRaw(String kid) throws Exception {
        // [CHECKPOINT id=JSEF-JWTKID-002 cwe=22 level=L3 source=kid header claim sink=new FileInputStream(kid) expect=VULN]
        FileInputStream fis = new FileInputStream(kid); // 未校验路径
        return fis.readAllBytes();
    }
}
