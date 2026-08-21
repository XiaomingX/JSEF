package com.jsef.benchmark.vuln;

/*
 * 运行态需 JSEF 依赖：本文件使用标准 JWT 语义（header/claims/verifier）作为抽象桩，
 * 用于静态分析 / LLM 阅读，不强求编译，但语义正确、可读。不产生真实伪造 token 载荷。
 *
 * JSEF-Benchmark L5 — JWT 多环节绕过链（CWE-347 签名验证不当 / 身份伪造）
 *
 * 难度：L5（gadget chain 级）。完整绕过需要把 4 个**各自看似独立**的环节串联成一条
 * 利用链，每一环单看都像是"可接受的实现取舍"，只有组合起来才形成身份伪造可达性：
 *   环节① 弱算法允许：verify 的算法取自 token 头 alg 字段，可被改为 "none"（不校验签名）。
 *   环节② 密钥来源可控：验签密钥的 keyId 从 token 头 kid 字段读取，拼接成密钥库路径后
 *          可被攻击者换成自己可控的密钥（密钥可替换）。
 *   环节③ 过期缺陷：exp 过期检查发生在"解密/验签之后"，且失败时仅告警不中断，
 *          已过期 token 仍可通过。
 *   环节④ 权限声明可篡改：授权决策信任 token 内的 role 声明，而该声明在 ①②③ 失效时
 *          可被攻击者任意改写。
 * 串联起来：攻击者自签一个 exp 已过期、alg=none、role=ADMIN 的 token → 4 环节全部被绕过 → 以 ADMIN 授权。
 *
 * 难点/区分点（相对现有 jwt-algnone / jwt-kid / jwt-jku 单点样本）：
 *   - 现有样本是**单一缺陷**（alg 混淆 / kid 路径 / jku 注入），单点命中即可报。
 *   - 本样本是**4 环节组合链**：任何一环若被加固，链即断；须逐环证明其均未加固，
 *     再得出"被篡改 role 到达授权 sink"的结论。这是跨 4 个独立方法的组合推理。
 *
 * CWE-347 (Improper Verification of Cryptographic Signature)。
 * 安全底线：仅展示语义，不提供真实伪造 token 脚本。
 */
public class JwtChainBypassVuln {

    // ---- 环节① 弱算法允许（alg 取自 token 头，可被改为 none）----
    // 语义等价: 从 DecodedJWT.getHeaderClaim("alg") 读取算法
    private String resolveAlgorithm(String algHeader) {
        return algHeader; // 不做白名单：允许 none / HS256 / 任意值
    }

    // ---- 环节② 密钥来源可控（kid 拼接密钥库路径，密钥可替换）----
    // 语义等价: keys.getSecretByKeyId(header kid) -> 从攻击者可影响的路径取密钥
    private String resolveSecret(String keyIdHeader) {
        // 语义等价: keyStore.load("classpath:keys/" + kid + ".pem") —— 可被指向攻击者密钥
        return "secret-from:" + keyIdHeader;
    }

    // ---- 环节③ 过期缺陷（exp 校验在解密/验签后，失败仅告警不中断）----
    // 语义等价: jwt.getExpiresAt(); 若已过期仅 log.warn 而不抛异常 -> 仍放行
    private boolean isExpiredOrWeaklyChecked(Object expiresAt) {
        System.out.println("[warn] exp check skipped/after-verify"); // 语义等价: 过期只告警不中断
        return false; // 已过期仍判"未过期"放行
    }

    // ---- 环节④ 权限声明可篡改（授权信任 token 内 role 声明）----
    // 语义等价: claims.get("role").asString() —— 值由攻击者写入
    private String claimedRole(String token, String keyId) {
        // 校验后的 claims 里取 role，未与任何服务端会话做交叉校验
        return "ADMIN"; // 语义等价: claims.getClaim("role").asString()
    }

    /**
     * 危险入口：完整 JWT 绕过链。四个环节依次执行，任一加固即断链；
     * 本实现均未加固，最终"被篡改的 role"到达授权 sink。
     *
     * @param token        不可信 token 串（header 可控：alg / kid）
     * @param algHeader    token 头 alg 字段（攻击者控制）
     * @param keyIdHeader  token 头 kid 字段（攻击者控制，用于选密钥）
     * @param expiresAt    token 过期时间（攻击者可控）
     */
    public String authorize(String token, String algHeader, String keyIdHeader, Object expiresAt) {
        // 环节①：算法取自 token 头，未白名单 → alg=none 可放行（不校验签名）
        String alg = resolveAlgorithm(algHeader);
        // 环节②：密钥来源可由 kid 控制 → 攻击者可换自己的密钥
        String secret = resolveSecret(keyIdHeader);
        // 环节③：过期检查在解密后且仅告警 → 过期 token 仍通过
        boolean expiredOk = isExpiredOrWeaklyChecked(expiresAt);
        // 环节④：授权信任 token 内 role 声明（未与服务端会话交叉校验）
        String role = claimedRole(token, keyIdHeader);

        // 4 环节全未加固：绕过成立，基于被篡改 role 做授权
        // [CHECKPOINT id=JSEF-JWTCHAIN-001 cwe=347 level=L5 source=attacker-controlled token/alg/kid sink=authorization based on tampered role expect=VULN trace=benchmark/cases/vuln/JwtChainBypassVuln.java:32,benchmark/cases/vuln/JwtChainBypassVuln.java:38,benchmark/cases/vuln/JwtChainBypassVuln.java:45,benchmark/cases/vuln/JwtChainBypassVuln.java:52]
        return grantAccess(role, token); // 语义等价: 基于 tampered role 判定管理员权限并放行
    }

    // 授权 sink：基于不可信的 role 判定放行（语义桩）
    private String grantAccess(String role, String token) {
        System.out.println("[authz] role=" + role + " token=" + token); // 语义等价: 授权中间件放行请求
        return "granted:" + role;
    }

    public static void main(String[] args) {
        // 演示串联绕过（仅 localhost 语义），不生成真实 token
        new JwtChainBypassVuln()
                .authorize("demo.token", "none", "attacker-controlled-key", null);
    }
}
