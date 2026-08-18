// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 — 组合 gadget chain：多租户隔离缺陷 + 权限提升 (CWE-863)
 *
 * 区分度来源（L5 组合链，非单一弱点）：
 *   本样本刻意把两个"单独看不致命"的弱点组合成可达危险操作：
 *     (a) TenantIsolationService 的租户归属检查只比 prefix（可绕过）；
 *     (b) RoleElevationService 的角色提升缺调用者权限校验（可提权）。
 *   两者组合：攻击者以低权租户身份，借 prefix 绕过隔离 + 自提角色，
 *   最终在 CrossTenantAdminService 以 ADMIN 身份跨租户执行管理操作。
 *
 * 跨 4 个编译单元：
 *   TenantAdminController (source: X-Tenant-Id + role + targetTenant)
 *     -> TenantIsolationService.belongsTo(tenant, target)   [弱前缀比较]
 *     -> RoleElevationService.elevate(role)                 [无调用者校验]
 *     -> CrossTenantAdminService.run(targetTenant, op)      [sink: 跨租户管理操作]
 *
 * VulnGym 范式对齐：BL-AUTHZ-BROKEN + BL-PRIV-ESC 组合（多安全类可达性）。
 * 单弱点 SAST 会各自放行；只有理解"组合可达性"的分析器才能判定。
 */
@RestController
public class TenantAdminController {

    private final TenantIsolationService isolation;
    private final RoleElevationService elevation;
    private final CrossTenantAdminService admin;

    public TenantAdminController(TenantIsolationService isolation,
                                 RoleElevationService elevation,
                                 CrossTenantAdminService admin) {
        this.isolation = isolation;
        this.elevation = elevation;
        this.admin = admin;
    }

    @PostMapping("/api/v1/tenant/admin")
    public String adminOp(@RequestHeader("X-Tenant-Id") String tenantId,
                          @RequestHeader("X-Role") String role,
                          @RequestParam("targetTenant") String targetTenant,
                          @RequestParam("op") String op) {
        // 入口：tenantId / role / targetTenant 均外部可控（source）
        // 弱点(a)：前缀比较可被 "acme" 匹配 "acme-evil" 绕过隔离
        boolean isolated = isolation.belongsTo(tenantId, targetTenant);
        // 弱点(b)：elevate 无调用者权限校验，低权可自提 ADMIN
        String elevated = elevation.elevate(role);
        // [CHECKPOINT id=JSEF-BIZ5-863C-001 cwe=863 level=L5 source=X-Tenant-Id+X-Role+targetTenant sink=CrossTenantAdminService.run expect=VULN trace=benchmark/cases/vuln/bizlogic5/TenantIsolationService.java:14,benchmark/cases/vuln/bizlogic5/RoleElevationService.java:14,benchmark/cases/vuln/bizlogic5/CrossTenantAdminService.java:14]
        return admin.run(targetTenant, op, elevated, isolated); // 组合绕过：跨租户+提权
    }
}
