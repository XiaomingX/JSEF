// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 — 修复版：Tenant-Bound Authorization (CWE-639 修复)
 *
 * 差异：DataService 查询时强制绑定 TenantContext.getTenant()，
 *      并校验 invoiceId 归属当前租户；越权请求返回 denied。
 */
@RestController
public class TenantInvoiceControllerSafe {

    private final TenantContextSafe tenantContext;
    private final TenantDataServiceSafe dataService;

    public TenantInvoiceControllerSafe(TenantContextSafe tenantContext,
                                       TenantDataServiceSafe dataService) {
        this.tenantContext = tenantContext;
        this.dataService = dataService;
    }

    @GetMapping("/api/v1/invoices")
    public String getInvoice(@RequestHeader("X-Tenant-Id") String tenantId,
                             @RequestParam("invoiceId") String invoiceId) {
        tenantContext.setTenant(tenantId);
        // 安全：查询由 DataService 内部绑定租户，越权访问被拒
        // [CHECKPOINT id=JSEF-BIZ5-639-001S cwe=639 level=L5 source=@RequestParam invoiceId sink=TenantDataServiceSafe.loadInvoice expect=SAFE trace=benchmark/cases/sec/bizlogic5/TenantContextSafe.java:12,benchmark/cases/sec/bizlogic5/TenantDataServiceSafe.java:21]
        return dataService.loadInvoice(invoiceId);
    }
}
