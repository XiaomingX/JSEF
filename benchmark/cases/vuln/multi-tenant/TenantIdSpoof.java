/*
 * JSEF Benchmark 样本 — 多租户隔离失效：tenant_id 来自客户端可伪造（VulnGym 子类 BL-MULTI-TENANT，CWE-285，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"租户来源语义"——tenant_id 由请求体传入并直接用于数据隔离，攻击者篡改即可越权访问
 * 其他租户数据。数据流干净，但隔离维度来源不可信。静态分析需在 query(tenantId) 处识别"tenant 来自不可信输入"。
 */
package com.jsef.benchmark.vuln;

public class TenantIdSpoof {

    // 演示用：请求与仓储
    static final class Req { String tenantId; }
    static final class Data { final String body; Data(String b){ this.body=b; } }
    interface Repo { Data findByTenant(String tenant); }

    // 危险：tenant_id 取自请求体直接用于查询
    static Data load(Repo repo, Req req) {
        // source：不可信 req.tenantId（HTTP 参数，可伪造）
        // [CHECKPOINT id=JSEF-V1-TNT-002 cwe=285 level=L4 source=req.tenantId (client-supplied) sink=repo.findByTenant(tenantId) expect=VULN]
        return repo.findByTenant(req.tenantId);   // 越权：伪造 tenant 读他人数据
    }
}
