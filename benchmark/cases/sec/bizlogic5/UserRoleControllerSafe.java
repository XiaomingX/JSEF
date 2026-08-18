// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 — 修复版：Privilege Management (CWE-269 修复)
 *
 * 差异：RoleService 校验调用者角色 + 禁止 self-promotion，越权被拒。
 */
@RestController
public class UserRoleControllerSafe {

    private final RoleServiceSafe roleService;

    public UserRoleControllerSafe(RoleServiceSafe roleService) {
        this.roleService = roleService;
    }

    @PostMapping("/api/v1/users/role")
    public String changeRole(@RequestBody RoleChangeRequestSafe req) {
        // 安全：权限校验在 RoleService 内部完成
        // [CHECKPOINT id=JSEF-BIZ5-269-001S cwe=269 level=L5 source=request body targetUserId+newRole sink=RoleServiceSafe.updateRole expect=SAFE trace=benchmark/cases/sec/bizlogic5/RoleServiceSafe.java:22,benchmark/cases/sec/bizlogic5/UserStoreSafe.java:9]
        return roleService.updateRole(req.getCallerRole(), req.getTargetUserId(), req.getNewRole());
    }

    public static class RoleChangeRequestSafe {
        private String callerRole;
        private String targetUserId;
        private String newRole;

        public String getCallerRole() { return callerRole; }
        public String getTargetUserId() { return targetUserId; }
        public String getNewRole() { return newRole; }
    }
}
