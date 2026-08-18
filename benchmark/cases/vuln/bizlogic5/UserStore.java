// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * 用户存储（危险 sink：持久化角色）。
 *
 * 语义等价：UPDATE users SET role=? WHERE id=?。
 * 缺陷：角色被外部请求直接写入，无权限闸门。
 */
public class UserStore {

    /** 危险终点：持久化角色变更。 */
    public String persistRole(String userId, String role) {
        // 语义等价：jdbcTemplate.update("UPDATE users SET role=? WHERE id=?", role, userId)
        // [CHECKPOINT id=JSEF-BIZ5-269-003 cwe=269 level=L5 source=attacker-controlled role sink=role persistence expect=VULN trace=benchmark/cases/vuln/bizlogic5/UserRoleController.java:34,benchmark/cases/vuln/bizlogic5/RoleService.java:21]
        System.out.println("[db-update] UPDATE users SET role='" + role + "' WHERE id='" + userId + "'");
        return "role-updated";
    }
}
