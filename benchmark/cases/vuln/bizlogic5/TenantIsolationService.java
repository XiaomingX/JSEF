// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * 租户隔离服务（组合链弱点 a：弱前缀比较）。
 *
 * 语义等价：WHERE tenant_id = ? 的归属判断。
 * 缺陷：belongsTo 用 startsWith 做租户归属，攻击者可构造
 *       "acme-attacker" 让 startsWith("acme") 为真，绕过跨租户隔离。
 */
public class TenantIsolationService {

    /** 危险节点 a：前缀比较而非精确相等，隔离可被绕过。 */
    public boolean belongsTo(String callerTenant, String targetTenant) {
        // [CHECKPOINT id=JSEF-BIZ5-863C-002 cwe=863 level=L5 source=prefix-bypassable tenant check sink=startsWith isolation decision expect=VULN trace=benchmark/cases/vuln/bizlogic5/TenantAdminController.java:50,benchmark/cases/vuln/bizlogic5/RoleElevationService.java:14,benchmark/cases/vuln/bizlogic5/CrossTenantAdminService.java:14]
        return targetTenant.startsWith(callerTenant); // 弱隔离：前缀匹配可绕过
    }
}
