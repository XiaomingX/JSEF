// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * 跨租户管理服务（危险 sink：组合链终点）。
 *
 * 语义等价：以 ADMIN 身份在 targetTenant 执行管理操作（如删除数据、改配置）。
 * 缺陷：run 信任前两个弱服务的判断（isolation + elevation），
 *      组合绕过后对目标租户执行高危操作 = 跨租户越权 + 提权。
 */
public class CrossTenantAdminService {

    /** 危险终点：跨租户管理操作，依赖被绕过的前置检查。 */
    public String run(String targetTenant, String op, String role, boolean isolated) {
        // [CHECKPOINT id=JSEF-BIZ5-863C-004 cwe=863 level=L5 source=combined bypass (tenant prefix + role elevation) sink=cross-tenant admin operation expect=VULN trace=benchmark/cases/vuln/bizlogic5/TenantAdminController.java:50,benchmark/cases/vuln/bizlogic5/TenantIsolationService.java:14,benchmark/cases/vuln/bizlogic5/RoleElevationService.java:14]
        System.out.println("[cross-tenant-admin] tenant=" + targetTenant
                + " op=" + op + " as=" + role);
        return "done:" + targetTenant;
    }
}
