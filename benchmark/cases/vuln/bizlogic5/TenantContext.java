// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * 租户上下文（多租户隔离边界）。
 *
 * 语义等价：Spring 的 RequestContextHolder / TenantContextHolder。
 * 设计意图：所有数据访问应以 tenantId 为隔离维度。
 * 缺陷不在本类，而在下游 DataService 未消费本上下文做归属校验。
 */
public class TenantContext {

    private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

    public void setTenant(String tenantId) {
        // 注入当前租户（隔离边界建立点）
        // [CHECKPOINT id=JSEF-BIZ5-639-002 cwe=639 level=L5 source=request-controlled tenantId sink=threadlocal store expect=VULN trace=benchmark/cases/vuln/bizlogic5/TenantInvoiceController.java:34,benchmark/cases/vuln/bizlogic5/TenantDataService.java:16]
        CURRENT.set(tenantId);
    }

    public String getTenant() {
        return CURRENT.get();
    }
}
