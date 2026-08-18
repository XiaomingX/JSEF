// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * 角色服务（安全版）：真实实现调用者权限校验 + 禁止自我提权。
 *
 * 评分约定：SAFE 侧按实现判定。
 */
public class RoleServiceSafe {

    private final UserStoreSafe userStore;

    public RoleServiceSafe(UserStoreSafe userStore) {
        this.userStore = userStore;
    }

    public String updateRole(String callerRole, String userId, String newRole) {
        // 真实实现了权限闸门：仅 ADMIN 可改角色，且禁止 self-promotion
        if (!"ADMIN".equals(callerRole)) {
            return "denied: insufficient privilege";
        }
        // [CHECKPOINT id=JSEF-BIZ5-269-002S cwe=269 level=L5 source=caller role gate sink=UserStoreSafe.persistRole expect=SAFE trace=benchmark/cases/sec/bizlogic5/UserRoleControllerSafe.java:34,benchmark/cases/sec/bizlogic5/UserStoreSafe.java:9]
        return userStore.persistRole(userId, newRole);
    }
}
