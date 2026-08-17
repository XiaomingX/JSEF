package com.jsef.benchmark.sec;

import java.security.PublicKey;
import java.util.Map;

/*
 * JSEF-Benchmark L4 — JWT jku 头劫持修复
 *
 * 修复：完全忽略 token 头中的 jku 字段，使用本地白名单 kid 固定的公钥验签，
 * 公钥来源可信、不依赖远程拉取。
 *
 * CWE-347 (Improper Verification of Cryptographic Signature)。
 */
public class JwtJkuSafe {

    static final PublicKey TRUSTED_KEY = null; // 占位：本地白名单绑定的公钥

    public boolean verify(String token, Map<String, Object> header) {
        // 忽略 jku，固定本地公钥（按 kid 白名单选择，此处简化为单一可信公钥）
        // [CHECKPOINT id=JSEF-NV103S cwe=347 level=L4 source=jku header URL sink=JWT verify using local whitelist kid pinned publicKey expect=SAFE]
        return verifyWith(TRUSTED_KEY, token); // 公钥来源可信，拒绝远程 jku
    }

    static boolean verifyWith(PublicKey pk, String token) { return true; }
}
