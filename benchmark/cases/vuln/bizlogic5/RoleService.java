// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * 角色服务（权限提升根因）。
 *
 * 语义等价：userRepository.updateRole(...)。
 * 缺陷：updateRole 直接执行角色变更，未校验调用者是否持有管理员权限，
 *      也未禁止将角色提升至 ADMIN，导致任意用户可提权。
 */
public class RoleService {

    private final UserStore userStore;

    public RoleService(UserStore userStore) {
        this.userStore = userStore;
    }

    /** 危险中间节点：无调用者权限校验，直接透传角色变更。 */
    public String updateRole(String userId, String newRole) {
        // [CHECKPOINT id=JSEF-BIZ5-269-002 cwe=269 level=L5 source=unprivileged caller sink=UserStore.persistRole expect=VULN trace=benchmark/cases/vuln/bizlogic5/UserRoleController.java:34,benchmark/cases/vuln/bizlogic5/UserStore.java:15]
        return userStore.persistRole(userId, newRole); // 任意用户均可提权至 ADMIN
    }
}
