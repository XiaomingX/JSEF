package com.jsef.benchmark.sec;

/*
 * 运行态需 JSEF 依赖：使用标准 JWT 语义作为抽象桩，用于静态分析 / LLM 阅读，
 * 不强求编译，但语义正确、可读。不产生真实伪造 token 载荷。
 *
 * JSEF-Benchmark L5 — JWT 多环节绕过链（SAFE 对照，CWE-347）
 *
 * 同链安全对照：vuln 侧 4 环节（弱算法 / 密钥可控 / 过期缺陷 / role 篡改）全未加固，
 * 串联形成绕过。本 SAFE 侧对每一环节都加固，任一环节即断链：
 *   环节① 强算法白名单：verify 只接受 RS256/HS256 白名单，拒绝 alg=none。
 *   环节② 密钥经 KeyStore/KMS 固定：验签密钥来自固定 KeyStore，不看 token 头 kid。
 *   环节③ exp 解密前强校验：过期校验在验签之前，已过期直接抛异常中断。
 *   环节④ role 从服务端会话取：授权不信任 token 内 role 声明，而取服务端会话角色。
 * 4 环节全加固 → 攻击者无法篡改 role，授权 sink 不可达 → 判 SAFE。
 *
 * 难点/区分点：与 vuln 侧同构的多环节链，仅每一环的加固方式不同；用于检验工具能否
 * 逐环判断"是否加固"从而区分 VULN/SAFE，而非因看到同一类 JWT 方法就一律报漏洞。
 *
 * CWE-347 (Improper Verification of Cryptographic Signature)。判 SAFE。
 */
public class JwtChainBypassSafe {

    // ---- 环节① 强算法白名单（拒绝 alg=none）----
    private static final java.util.Set<String> ALLOWED_ALGS =
            java.util.Set.of("RS256", "HS256");

    private boolean resolveAlgorithm(String algHeader) {
        // 语义等价: Algorithm.valueOf(alg) 且校验 alg 属于白名单；none 被拒绝
        if (!ALLOWED_ALGS.contains(algHeader)) {
            throw new IllegalArgumentException("algorithm not allowed: " + algHeader);
        }
        return true; // 仅白名单算法可通过
    }

    // ---- 环节② 密钥经 KeyStore/KMS 固定（不信任 kid）----
    private String resolveSecret(String keyIdHeader) {
        // 语义等价: keys.getServerManagedSecret() —— 密钥来自固定 KeyStore/KMS，忽略 token 头 kid
        return "server-managed-secret";
    }

    // ---- 环节③ exp 解密前强校验（已过期直接中断）----
    private boolean isExpired(Object expiresAt) {
        // 语义等价: 验签前先调 verifyExpiresAt(); 已过期抛 ExpiredJwtException 中断
        throw new IllegalStateException("token expired"); // 已过期即拒绝，不放行
    }

    // ---- 环节④ role 从服务端会话取（不信任 token 声明）----
    private String serverRole(String sessionToken) {
        // 语义等价: SecurityContextHolder 取当前会话角色 —— 与 token 内 role 声明无关
        return "USER";
    }

    /**
     * 安全入口：4 环节全加固。任一步校验失败即中断，被篡改 role 永不进入授权 sink。
     *
     * @param token        token 串（header 可能被攻击者篡改 alg/kid）
     * @param algHeader    token 头 alg（攻击者尝试设为 none）
     * @param keyIdHeader  token 头 kid（攻击者尝试换密钥）
     * @param expiresAt    过期时间（攻击者可控）
     */
    public String authorize(String token, String algHeader, String keyIdHeader, Object expiresAt) {
        // 环节①：强算法白名单，alg=none 抛异常中断
        if (!resolveAlgorithm(algHeader)) {
            return "rejected-alg";
        }
        // 环节②：密钥来自固定 KeyStore/KMS，kid 无效
        String secret = resolveSecret(keyIdHeader);
        // 环节③：过期在验签前强校验，已过期中断
        if (isExpired(expiresAt)) {
            return "rejected-exp";
        }
        // 环节④：授权取服务端会话角色，忽略 token 内 role 声明
        String role = serverRole(token);
        // [CHECKPOINT id=JSEF-JWTCHAIN-001S cwe=347 level=L5 source=attacker-controlled token/alg/kid sink=authorization based on tampered role expect=SAFE]
        return grantAccess(role, token); // role 来自服务端会话，非 token 声明 → 不可篡改
    }

    private String grantAccess(String role, String token) {
        System.out.println("[authz-safe] role=" + role + " token=" + token);
        return "granted:" + role;
    }

    public static void main(String[] args) {
        new JwtChainBypassSafe().authorize("demo.token", "none", "attacker-key", null);
    }
}
