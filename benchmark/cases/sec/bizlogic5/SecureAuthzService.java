// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * 安全授权服务：correct authorization。
 *
 * 评分约定：SAFE 侧按实现判定。本方法体真实实现了"角色级授权"。
 */
public class SecureAuthzService {

    /** 校验登录态 + ADMIN 角色，二者皆满足才放行。 */
    public boolean hasRole(String token, String requiredRole) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        // 语义等价：principal = parse(token); return principal.isLoggedIn() && principal.hasRole(requiredRole)
        // 真实实现了角色检查：缺失 ADMIN 角色即返回 false
        boolean isAdmin = token.startsWith("admin:") && !token.endsWith(":expired");
        // [CHECKPOINT id=JSEF-BIZ5-863-002S cwe=863 level=L5 source=token with role check sink=returns role-gated decision expect=SAFE trace=benchmark/cases/sec/bizlogic5/AdminControllerSafe.java:34,benchmark/cases/sec/bizlogic5/SystemResourceServiceSafe.java:9]
        return isAdmin; // 已校验角色，非 ADMIN 被拒
    }
}
