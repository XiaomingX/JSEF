package com.jsef.benchmark.vuln;

import java.io.InputStream;
import java.net.URL;
import java.security.PublicKey;
import java.util.Map;

/*
 * JSEF-Benchmark L4 — JWT jku 头劫持（SSRF + 公钥投毒）
 *
 * 难度：L4（跨方法 / 不可信远程源）。服务端从 token 头的 jku 字段读取 JWKS
 * URL，然后访问该 URL 拉取公钥用于验签。攻击者可伪造 jku 指向自己控制的
 * 服务器（返回自己生成的公钥），从而伪造任意 token（同时构成 SSRF）。
 *
 * CWE-347 (Improper Verification of Cryptographic Signature)。
 * 安全底线：仅 localhost 演示语义，不提供真实伪造代码。
 *
 * 修复要点（对照 JwtJkuSafe.java）：忽略 jku，使用本地白名单 kid 固定的公钥。
 */
public class JwtJkuVuln {

    public PublicKey fetchJwks(String jwksUrl) throws Exception {
        // 从不可信 URL 拉取 JWKS——攻击者可控内容（SSRF + 公钥投毒）
        try (InputStream is = new URL(jwksUrl).openStream()) {
            return parsePubKey(is);
        }
    }

    public boolean verify(String token, Map<String, Object> header) throws Exception {
        String jwksUrl = (String) header.get("jku"); // 污点：jku 来自不可信 token 头
        PublicKey pk = fetchJwks(jwksUrl); // 用不可信公钥验签
        // [CHECKPOINT id=JSEF-NV103 cwe=347 level=L4 source=jku header URL sink=JWT verify using fetched JWKS (SSRF+pubkey poison) expect=VULN trace=benchmark/cases/vuln/jwt-jku/JwtJkuVuln.java:31,benchmark/cases/vuln/jwt-jku/JwtJkuVuln.java:33]
        return verifyWith(pk, token); // 用不可信公钥验签
    }

    static PublicKey parsePubKey(InputStream is) { return null; }
    static boolean verifyWith(PublicKey pk, String token) { return true; }
}
