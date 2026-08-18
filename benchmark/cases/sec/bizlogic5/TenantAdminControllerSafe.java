// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 — 修复版：组合链加固 (CWE-863 修复)
 *
 * 差异：
 *   (a) TenantIsolationServiceSafe.belongsTo 用精确相等（非前缀）；
 *   (b) RoleElevationServiceSafe.elevate 校验调用者 ADMIN 角色。
 *   两者皆加固后组合链不可达 sink。
 */
@RestController
public class TenantAdminControllerSafe {

    private final TenantIsolationServiceSafe isolation;
    private final RoleElevationServiceSafe elevation;
    private final CrossTenantAdminServiceSafe admin;

    public TenantAdminControllerSafe(TenantIsolationServiceSafe isolation,
                                     RoleElevationServiceSafe elevation,
                                     CrossTenantAdminServiceSafe admin) {
        this.isolation = isolation;
        this.elevation = elevation;
        this.admin = admin;
    }

    @PostMapping("/api/v1/tenant/admin")
    public String adminOp(@RequestHeader("X-Tenant-Id") String tenantId,
                          @RequestHeader("X-Role") String role,
                          @RequestParam("targetTenant") String targetTenant,
                          @RequestParam("op") String op) {
        // 安全：精确相等隔离 + 调用者权限闸门
        // [CHECKPOINT id=JSEF-BIZ5-863C-001S cwe=863 level=L5 source=X-Tenant-Id+X-Role+targetTenant sink=CrossTenantAdminServiceSafe.run expect=SAFE trace=benchmark/cases/sec/bizlogic5/TenantIsolationServiceSafe.java:12,benchmark/cases/sec/bizlogic5/RoleElevationServiceSafe.java:12,benchmark/cases/sec/bizlogic5/CrossTenantAdminServiceSafe.java:9]
        boolean isolated = isolation.belongsTo(tenantId, targetTenant);
        if (!isolated) {
            return "denied: cross-tenant";
        }
        String elevated = elevation.elevate(role); // 非 ADMIN 被拒
        if (!"ADMIN".equals(elevated)) {
            return "denied: insufficient privilege";
        }
        return admin.run(targetTenant, op);
    }
}
