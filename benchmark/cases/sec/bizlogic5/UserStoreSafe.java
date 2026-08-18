// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * 用户存储（安全版）。角色写入仅在 RoleServiceSafe 授权通过后发生。
 */
public class UserStoreSafe {

    public String persistRole(String userId, String role) {
        // 语义等价：UPDATE users SET role=? WHERE id=?  (仅 ADMIN 可达)
        System.out.println("[db-update][authorized] UPDATE users SET role='" + role + "' WHERE id='" + userId + "'");
        return "role-updated";
    }
}
