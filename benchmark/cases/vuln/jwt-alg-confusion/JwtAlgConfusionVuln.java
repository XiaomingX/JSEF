package com.jsef.benchmark.vuln;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.security.PublicKey;

/*
 * JSEF-Benchmark L3 — JWT 算法混淆（RS256 → HS256）
 *
 * 难度：L3（跨方法 / 间接）。服务端持有 RSA 公钥用于验证 RS256 签名，但
 * 验签时从 token 头部读取 alg 字段动态选择算法。若攻击者将 alg 改为 HS256，
 * 服务端会用 publicKey.getEncoded() 作为 HMAC 密钥验签——而公钥是公开信息，
 * 攻击者可用公钥伪造任意 token。
 *
 * CWE-347 (Improper Verification of Cryptographic Signature)。
 * 安全底线：仅 localhost 演示语义，不提供真实伪造代码。
 *
 * 修复要点（对照 JwtAlgConfusionSafe.java）：固定 Algorithm.RS256 + 公钥验签，
 * 拒绝 alg 字段变更。
 */
public class JwtAlgConfusionVuln {

    static final PublicKey PUBLIC_KEY = null; // 占位：真实场景为服务器 RSA 公钥

    /**
     * 危险路径：alg 取自不可信 token 头，HS256 时用公钥字节当 HMAC 密钥。
     *
     * @param token    用户可控 JWT
     * @param header   解析出的 JWT 头部
     */
    public boolean verify(String token, java.util.Map<String, Object> header) throws Exception {
        String alg = (String) header.get("alg"); // 污点：alg 来自不可信 token 头
        if ("HS256".equals(alg)) {
            // 公钥字节被当作 HMAC 密钥——攻击者持公钥即可伪造
            byte[] secret = PUBLIC_KEY.getEncoded();
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] sig = mac.doFinal(token.split("\\.")[0].getBytes(StandardCharsets.UTF_8));
            String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
            // [CHECKPOINT id=JSEF-NV102 cwe=347 level=L3 source=token.alg header sink=JWT.verify (RS256→HS256, publicKey as HMAC secret) expect=VULN]
            return expected.equals(token.split("\\.")[2]); // 用公钥字节验 HS256 签名
        }
        return false;
    }
}
