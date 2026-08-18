// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 — 业务逻辑漏洞：Authorization Bypass Through User-Controlled Key (CWE-639)
 *
 * 多租户 SaaS 场景的横向越权（IDOR 跨租户）。
 *
 * 区分度来源（L5）：
 *   系统设计了 TenantContext 承载"当前租户"用于数据隔离。但若查询条件直接取
 *   自请求参数 `invoiceId` 而非严格绑定 TenantContext.tenantId，攻击者可构造他人
 *   invoiceId 越权读取。污点跨 3 个编译单元 + 状态机（租户上下文由过滤器注入）：
 *     TenantInvoiceController (source: @RequestHeader X-Tenant-Id + @RequestParam invoiceId)
 *       -> TenantContext.setTenant / getTenant   [租户隔离上下文]
 *       -> TenantDataService.loadInvoice(invoiceId)  [sink: 按 invoiceId 查库，未校验归属]
 *
 * VulnGym 范式对齐：BL-AUTHZ-BROKEN（授权逻辑破坏）—— 隔离边界被破坏。
 */
@RestController
public class TenantInvoiceController {

    private final TenantContext tenantContext;
    private final TenantDataService dataService;

    public TenantInvoiceController(TenantContext tenantContext,
                                   TenantDataService dataService) {
        this.tenantContext = tenantContext;
        this.dataService = dataService;
    }

    @GetMapping("/api/v1/invoices")
    public String getInvoice(@RequestHeader("X-Tenant-Id") String tenantId,
                             @RequestParam("invoiceId") String invoiceId) {
        // 入口：tenantId 来自请求头，invoiceId 来自请求参数（二者均外部可控）
        tenantContext.setTenant(tenantId); // 注入租户上下文（隔离边界起点）
        // 缺陷：查询直接用请求参数 invoiceId，未与 tenantContext.tenantId 做归属校验
        // [CHECKPOINT id=JSEF-BIZ5-639-001 cwe=639 level=L5 source=@RequestParam invoiceId (cross-tenant) sink=TenantDataService.loadInvoice expect=VULN trace=benchmark/cases/vuln/bizlogic5/TenantContext.java:17,benchmark/cases/vuln/bizlogic5/TenantDataService.java:16]
        return dataService.loadInvoice(invoiceId); // 可越权读取其他租户发票
    }
}
