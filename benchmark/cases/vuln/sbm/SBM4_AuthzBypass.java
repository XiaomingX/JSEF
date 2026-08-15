package com.jsef.benchmark.vuln.sbm;

/**
 * SBM-4 AuthZ Bypass by Short-circuit（授权被短路绕过）
 *
 * 对应「授权决策被短路绕过」类：授权决策依赖可被攻击者操纵的条件
 * （用户可控字段 / 可伪造请求头或 URL 前缀），导致授权判断被短路跳过。
 * 本文件与具体安全框架完全解耦，用普通 Java 类模拟请求与授权决策。
 *
 * 维度：框架机制 SBM 原子范式 —— 授权短路。仅 localhost 演示语义。
 */
public class SBM4_AuthzBypass {

    /** 抽象请求对象 */
    public static class Request {
        public String role;
        public String override;     // 用户可控的越权开关
        public String headerSecret; // 可伪造的内部密钥头
        public String url;          // 可伪造的请求 URL
    }

    /** 抽象授权决策 */
    public enum AuthorizationDecision {
        ALLOW, DENY
    }

    /**
     * L2：先判 role==admin，再判用户可控的 override 字段 → 短路放行。
     */
    // [VULN] 授权依赖用户可控 override 字段，可短路跳过 role 检查
    public static AuthorizationDecision isAuthorized(Request req) {
        AuthorizationDecision decision = AuthorizationDecision.DENY;
        if (req.role != null && req.role.equals("admin")) {
            decision = AuthorizationDecision.ALLOW;
        } else if (req.override != null) {
            // 攻击者控制 override 即绕过
            decision = AuthorizationDecision.ALLOW;
        }
        // [CHECKPOINT id=JSEF-SBM-401 cwe=862 level=L2 source=user-controlled override field sink=AuthorizationDecision.ALLOW (short-circuit) expect=VULN]
        return decision;
    }

    /**
     * L4：授权依赖「X-Internal-Secret 请求头」或「特定前缀 URL」，二者均可被
     * 攻击者伪造，导致 decide() 返回 ALLOW（对应通用授权判定被伪造
     * 内部请求条件短路绕过）。
     * trace 节点：行1 = 伪造输入入口；行2 = return ALLOW。
     */
    // [VULN] 授权依赖可伪造 header/url 前缀，攻击者可构造绕过条件
    public static AuthorizationDecision decide(Request req) {
        AuthorizationDecision decision = AuthorizationDecision.DENY;
        if (req.headerSecret != null && req.headerSecret.equals("internal")) { // 行1：伪造输入入口
            decision = AuthorizationDecision.ALLOW;
        } else if (req.url != null && req.url.startsWith("/internal/")) {
            decision = AuthorizationDecision.ALLOW;
        }
        // [CHECKPOINT id=JSEF-SBM-402 cwe=862 level=L4 source=forged header/url-prefix sink=AuthorizationDecision.ALLOW expect=VULN trace=benchmark/cases/vuln/sbm/SBM4_AuthzBypass.java:52,benchmark/cases/vuln/sbm/SBM4_AuthzBypass.java:58]
        return decision; // 行2：return ALLOW
    }
}
