// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * 租户上下文（安全版）。评分约定：SAFE 侧按实现判定。
 */
public class TenantContextSafe {

    private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

    public void setTenant(String tenantId) {
        CURRENT.set(tenantId);
    }

    public String getTenant() {
        return CURRENT.get();
    }
}
