// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * 跨租户管理服务（安全版）：仅在隔离+授权均通过时执行。
 */
public class CrossTenantAdminServiceSafe {

    public String run(String targetTenant, String op) {
        // 语义等价：以已验证 ADMIN 身份在已验证同租户执行管理操作
        System.out.println("[cross-tenant-admin][safe] tenant=" + targetTenant + " op=" + op);
        return "done:" + targetTenant;
    }
}
