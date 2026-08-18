// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 — 业务逻辑漏洞：Improper Privilege Management (CWE-269)
 *
 * 权限提升：普通用户可修改任意用户的角色（含把自己提为 ADMIN）。
 *
 * 区分度来源（L5）：
 *   角色变更接口未校验"调用者是否有权修改目标用户角色"，也未禁止
 *   提升自身权限。污点跨 3 个编译单元：
 *     UserRoleController (source: 请求体 targetUserId + newRole)
 *       -> RoleService.updateRole(targetUserId, newRole)  [无调用者权限校验]
 *       -> UserStore.persistRole(userId, role)            [sink: 持久化角色]
 *
 * VulnGym 范式对齐：BL-PRIV-ESC（权限提升）—— 需理解"谁调用、改谁、改什么"。
 */
@RestController
public class UserRoleController {

    private final RoleService roleService;

    public UserRoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @PostMapping("/api/v1/users/role")
    public String changeRole(@RequestBody RoleChangeRequest req) {
        // 入口：targetUserId 与 newRole 均来自外部请求体（source）
        // 缺陷：未校验当前登录用户是否为管理员，也未禁止 self-promotion
        // [CHECKPOINT id=JSEF-BIZ5-269-001 cwe=269 level=L5 source=request body targetUserId+newRole sink=RoleService.updateRole expect=VULN trace=benchmark/cases/vuln/bizlogic5/RoleService.java:21,benchmark/cases/vuln/bizlogic5/UserStore.java:15]
        return roleService.updateRole(req.getTargetUserId(), req.getNewRole());
    }

    /** 简单请求载体。 */
    public static class RoleChangeRequest {
        private String targetUserId;
        private String newRole;

        public String getTargetUserId() { return targetUserId; }
        public String getNewRole() { return newRole; }
    }
}
