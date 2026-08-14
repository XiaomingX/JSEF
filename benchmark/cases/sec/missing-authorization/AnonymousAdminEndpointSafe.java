/*
 * JSEF Benchmark 样本 — 授权缺失：管理端点强制认证+授权（safe 对照，CWE-862，L4）
 * 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

public class AnonymousAdminEndpointSafe {

    // 安全：端点位于认证后上下文，且要求 ADMIN 角色
    // [CHECKPOINT id=JSEF-V1-AUT-002S cwe=862 level=L4 source=authenticated+authorized request sink=exportSecrets() (authn+authz enforced) expect=SAFE]
    @PreAuthorize("isAuthenticated() and hasRole('ADMIN')")
    static String exportSecrets(SecretStore store, User user) {
        if (!user.isAdmin()) throw new SecurityException("forbidden");
        return store.exportAll();
    }

    @interface PreAuthorize { String value(); }
    static final class User { boolean isAdmin(){ return false; } }
    interface SecretStore { String exportAll(); }
}
