// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * 角色提升服务（安全版）：校验调用者权限。
 *
 * 评分约定：SAFE 侧按实现判定。本方法体真实实现了调用者 ADMIN 校验。
 */
public class RoleElevationServiceSafe {

    /** 安全：仅 ADMIN 可保持/提升，低权调用者被降权拒绝。 */
    public String elevate(String currentRole) {
        // [CHECKPOINT id=JSEF-BIZ5-863C-003S cwe=863 level=L5 source=caller role gate sink=role elevation decision expect=SAFE trace=benchmark/cases/sec/bizlogic5/TenantAdminControllerSafe.java:43,benchmark/cases/sec/bizlogic5/TenantIsolationServiceSafe.java:12,benchmark/cases/sec/bizlogic5/CrossTenantAdminServiceSafe.java:9]
        return "ADMIN".equals(currentRole) ? "ADMIN" : "DENIED"; // 非 ADMIN 不可提权
    }
}
