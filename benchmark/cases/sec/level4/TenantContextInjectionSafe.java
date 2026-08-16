package com.jsef.benchmark.sec.level4;

import java.util.Map;
import java.util.Set;
import java.util.Arrays;
import java.util.HashSet;

/**
 * JSEF-Benchmark L4 安全对照 — 多租户上下文污点修复（CWE-284 / CWE-639，L4）
 *
 * 修复策略（对照 vuln）：
 *   ① JWT/Session 服务端校验：tenantId 从经过认证的 JWT Claims 中提取，
 *      而非从客户端可伪造的 HTTP Header 读取。
 *   ② 白名单校验：tenantId 还须在已知合法租户集合中，防止参数枚举。
 *   ③ 参数化查询：SQL 使用占位符而非字符串拼接，彻底消除注入风险。
 *
 * 安全底线：仅 localhost 演示语义，不提供真实越权利用工具。
 */
public class TenantContextInjectionSafe {

    static final ThreadLocal<String> TENANT = new ThreadLocal<>();

    // 模拟合法租户白名单（真实场景从数据库/配置中心加载）
    static final Set<String> ALLOWED_TENANTS = new HashSet<>(Arrays.asList(
            "tenant-a", "tenant-b", "tenant-c"
    ));

    /** 框架拦截器：从服务端签发的 JWT Claims 中提取 tenantId，拒绝 Header 伪造。 */
    public static void setContext(String jwtTenantClaim) {
        // 白名单校验：仅允许已注册租户，阻止参数枚举
        if (!ALLOWED_TENANTS.contains(jwtTenantClaim)) {
            throw new SecurityException("Unknown or unauthorized tenant: " + jwtTenantClaim);
        }
        // [CHECKPOINT id=JSEF-L4-TENANT-001S cwe=284 level=L4 source=JWT tenant claim (server-side) sink=TENANT ThreadLocal after whitelist check expect=SAFE]
        TENANT.set(jwtTenantClaim); // 源来自服务端签发的 JWT，已白名单校验
    }

    public static String getTenantId() {
        return TENANT.get();
    }

    /**
     * 数据访问层：使用参数化查询占位符（? / :param），消除 SQL 注入路径。
     * 真实场景中配合 JdbcTemplate.query(sql, tenantId, orderId) 执行。
     */
    public static String buildQuery(String orderId) {
        String tenantId = getTenantId(); // 已白名单校验的服务端值
        // 参数化查询：tenantId 与 orderId 均作为绑定参数，不拼入 SQL
        return "SELECT * FROM orders WHERE tenant_id=? AND id=?";
        // 实际执行: jdbcTemplate.query(sql, tenantId, orderId);
    }
}
