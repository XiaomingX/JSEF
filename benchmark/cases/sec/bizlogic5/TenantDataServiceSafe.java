// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * 租户数据服务（安全版）：查询强制绑定租户上下文。
 *
 * 评分约定：SAFE 侧按实现判定。本方法体真实实现了租户归属校验。
 */
public class TenantDataServiceSafe {

    private final TenantContextSafe tenantContext;

    public TenantDataServiceSafe(TenantContextSafe tenantContext) {
        this.tenantContext = tenantContext;
    }

    /** 安全终点：查询同时绑定 tenant_id，越权 invoiceId 无结果。 */
    public String loadInvoice(String invoiceId) {
        String tenant = tenantContext.getTenant();
        // 真实实现了租户归属绑定：WHERE id=? AND tenant_id=?
        // [CHECKPOINT id=JSEF-BIZ5-639-003S cwe=639 level=L5 source=invoiceId with tenant binding sink=tenant-scoped db query expect=SAFE trace=benchmark/cases/sec/bizlogic5/TenantInvoiceControllerSafe.java:34,benchmark/cases/sec/bizlogic5/TenantContextSafe.java:12]
        System.out.println("[db-query] SELECT * FROM invoices WHERE id='" + invoiceId
                + "' AND tenant_id='" + tenant + "'");
        return "invoice:" + invoiceId + "@" + tenant;
    }
}
