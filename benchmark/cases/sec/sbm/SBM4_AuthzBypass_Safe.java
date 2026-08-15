package com.jsef.benchmark.sec.sbm;

/**
 * SBM-4 AuthZ Bypass by Short-circuit —— 安全修复版
 *
 * 对应「授权决策被短路绕过」类的安全加固：
 * 授权不依赖任何用户可控字段 / 可伪造请求头或 URL，改为服务端强制权限矩阵
 * （基于调用方已认证身份在权限表中查表裁决）。
 *
 * 与具体安全框架完全解耦，仅用普通 Java 类模拟授权决策。
 */
public class SBM4_AuthzBypass_Safe {

    public static class Request {
        public String callerId; // 已认证身份（服务端设置，非用户可控）
        public String action;   // 请求的动作
    }

    public enum AuthorizationDecision {
        ALLOW, DENY
    }

    /**
     * 服务端强制权限矩阵：身份 -> 允许的动作集合（不可由请求伪造）。
     */
    private static boolean permitted(String callerId, String action) {
        // localhost-demo：仅占位矩阵
        return "svc-admin".equals(callerId) && "config.reload".equals(action);
    }

    /**
     * L2 修复：授权基于服务端强制权限矩阵，不再依赖用户可控 override 字段。
     */
    // [SAFE] 授权由服务端权限矩阵裁决，用户无法操纵
    public static AuthorizationDecision isAuthorized(Request req) {
        AuthorizationDecision decision;
        if (req.callerId != null && permitted(req.callerId, req.action)) {
            decision = AuthorizationDecision.ALLOW;
        } else {
            decision = AuthorizationDecision.DENY;
        }
        // [CHECKPOINT id=JSEF-SBM-401S cwe=862 level=L2 source=request sink=server-enforced permission matrix expect=SAFE]
        return decision;
    }

    /**
     * L4 修复：授权不再读取任何用户可控的 header/url 前缀条件。
     */
    // [SAFE] 不依赖任何用户可控的鉴权条件
    public static AuthorizationDecision decide(Request req) {
        AuthorizationDecision decision;
        if (req.callerId != null && permitted(req.callerId, req.action)) {
            decision = AuthorizationDecision.ALLOW;
        } else {
            decision = AuthorizationDecision.DENY;
        }
        // [CHECKPOINT id=JSEF-SBM-402S cwe=862 level=L4 source=request sink=no user-controlled authz condition expect=SAFE]
        return decision;
    }
}
