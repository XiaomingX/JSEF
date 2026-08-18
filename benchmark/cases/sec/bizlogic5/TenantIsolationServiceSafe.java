// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * 租户隔离服务（安全版）：精确相等比较。
 *
 * 评分约定：SAFE 侧按实现判定。本方法体真实实现了精确租户匹配。
 */
public class TenantIsolationServiceSafe {

    /** 安全：精确相等，前缀绕过不可行。 */
    public boolean belongsTo(String callerTenant, String targetTenant) {
        // [CHECKPOINT id=JSEF-BIZ5-863C-002S cwe=863 level=L5 source=exact tenant equality sink=equals isolation decision expect=SAFE trace=benchmark/cases/sec/bizlogic5/TenantAdminControllerSafe.java:43,benchmark/cases/sec/bizlogic5/RoleElevationServiceSafe.java:12,benchmark/cases/sec/bizlogic5/CrossTenantAdminServiceSafe.java:9]
        return targetTenant.equals(callerTenant); // 精确匹配，无前缀绕过
    }
}
