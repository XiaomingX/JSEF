// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * 授权服务（业务逻辑缺陷核心）。
 *
 * 语义等价：Spring Security 的 Authentication 校验。
 * 缺陷：isAuthenticated 只判断 token 非空且未过期（= 已登录），
 *      完全没有检查 principal 是否持有 ADMIN 角色。
 *      这是 CWE-863（Incorrect Authorization）而非 CWE-862（Missing Authorization）：
 *      授权**存在但错误**——把"已认证"误当作"已授权"。
 */
public class InsecureAuthzService {

    /** 仅校验登录态，缺失角色级授权判断（CWE-863 根因）。 */
    public boolean isAuthenticated(String token) {
        // 语义等价：token != null && !isExpired(token)
        if (token == null || token.isEmpty()) {
            return false;
        }
        // [CHECKPOINT id=JSEF-BIZ5-863-002 cwe=863 level=L5 source=authenticated token sink=returns true without role check expect=VULN trace=benchmark/cases/vuln/bizlogic5/AdminController.java:34,benchmark/cases/vuln/bizlogic5/SystemResourceService.java:15]
        return true; // 已登录即放行，未校验 ADMIN 角色 —— 授权判断错误
    }
}
