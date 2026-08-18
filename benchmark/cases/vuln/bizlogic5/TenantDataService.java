// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * 租户数据服务（危险 sink：按 invoiceId 直接查库）。
 *
 * 语义等价：jdbcTemplate.query("SELECT * FROM invoices WHERE id=?", invoiceId)。
 * 缺陷：直接用外部传入的 invoiceId 查询，未与 TenantContext.getTenant() 做
 *       `WHERE tenant_id = ?` 归属绑定，导致跨租户越权读取。
 */
public class TenantDataService {

    /** 危险终点：按 invoiceId 查库，无租户归属校验（CWE-639）。 */
    public String loadInvoice(String invoiceId) {
        // 语义等价：SELECT * FROM invoices WHERE id = ?  (缺少 AND tenant_id = ?)
        // [CHECKPOINT id=JSEF-BIZ5-639-003 cwe=639 level=L5 source=cross-tenant invoiceId sink=database query (no tenant binding) expect=VULN trace=benchmark/cases/vuln/bizlogic5/TenantInvoiceController.java:34,benchmark/cases/vuln/bizlogic5/TenantContext.java:17]
        System.out.println("[db-query] SELECT * FROM invoices WHERE id='" + invoiceId + "'");
        return "invoice:" + invoiceId;
    }
}
