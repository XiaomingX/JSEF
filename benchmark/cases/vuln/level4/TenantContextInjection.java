package com.jsef.benchmark.vuln.level4;

import java.util.Map;

/**
 * JSEF-Benchmark L4 — 多租户上下文污点 + IDOR（CWE-284 / CWE-639，L4）
 *
 * 场景：SaaS 订单系统按 tenantId 隔离数据。
 * 漏洞链：HTTP Header 中的 X-Tenant-Id 直接写入 ThreadLocal 上下文（TenantContext），
 * 后续查询用 getTenantId() 拼入 SQL → 攻击者伪造 header 即可访问他人租户数据。
 *
 * 区分度要点（L4）：
 *   - 污点源（HTTP Header）与 sink（SQL 拼接）跨越两个方法（setContext / buildQuery），
 *     并借助 ThreadLocal 字段传递——弱 SAST 丢失 ThreadLocal 传播路径。
 *   - tenantId 表面上"由业务层设置"，实则来自外部请求，框架语义理解是关键。
 *
 * 安全底线：仅 localhost 演示语义，不写真实越权利用脚本。
 *
 * 污点流（source → sink）：
 *   HTTP Header X-Tenant-Id
 *     → TenantContext.setContext(tenantId)   [写入 ThreadLocal，跨方法节点]
 *     → TenantContext.getTenantId()          [读出 ThreadLocal，跨方法节点]
 *     → buildQuery(tenantId) 拼 SQL          [sink：字符串拼接进查询]
 */
public class TenantContextInjection {

    // ------------------------------------------------------------------ //
    // ThreadLocal 上下文（模拟真实 SaaS 框架中的 TenantContext）
    // ------------------------------------------------------------------ //
    static final ThreadLocal<String> TENANT = new ThreadLocal<>();

    /** 框架拦截器在每次请求开头调用：从 HTTP Header 读 tenantId 写入 ThreadLocal。 */
    public static void setContext(Map<String, String> headers) {
        String tenantId = headers.get("X-Tenant-Id"); // [VULN] 不可信源：外部 HTTP Header
        TENANT.set(tenantId);  // 污点写入 ThreadLocal；trace 节点
    }

    /** 业务层：读取当前租户 ID，拼接查询条件。 */
    public static String getTenantId() {
        return TENANT.get(); // 污点从 ThreadLocal 读出；trace 节点
    }

    /** 数据访问层：将 tenantId 直接拼入 SQL，触发 IDOR（数据越权）。 */
    public static String buildQuery(String orderId) {
        String tenantId = getTenantId(); // 污点流入
        // [CHECKPOINT id=JSEF-L4-TENANT-001 cwe=284 level=L4 source=HTTP Header X-Tenant-Id sink=SQL string concat via ThreadLocal expect=VULN trace=benchmark/cases/vuln/level4/TenantContextInjection.java:38,benchmark/cases/vuln/level4/TenantContextInjection.java:43]
        return "SELECT * FROM orders WHERE tenant_id='" + tenantId + "' AND id='" + orderId + "'";
        // 攻击者伪造 X-Tenant-Id: victim-corp → 跨越租户访问他人订单
    }
}
