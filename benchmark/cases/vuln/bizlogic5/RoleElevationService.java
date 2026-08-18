// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * 角色提升服务（组合链弱点 b：无调用者权限校验）。
 *
 * 语义等价：UPDATE users SET role='ADMIN'。
 * 缺陷：elevate 直接把传入角色当作结果返回，未校验调用者是否已是 ADMIN，
 *      也未禁止 self-promotion —— 低权用户可自提 ADMIN。
 */
public class RoleElevationService {

    /** 危险节点 b：无调用者权限闸门，角色可被任意提升。 */
    public String elevate(String currentRole) {
        // [CHECKPOINT id=JSEF-BIZ5-863C-003 cwe=863 level=L5 source=unprivileged role sink=returns elevated role expect=VULN trace=benchmark/cases/vuln/bizlogic5/TenantAdminController.java:50,benchmark/cases/vuln/bizlogic5/TenantIsolationService.java:14,benchmark/cases/vuln/bizlogic5/CrossTenantAdminService.java:14]
        return "ADMIN"; // 任何角色传入都被提为 ADMIN（无校验）
    }
}
