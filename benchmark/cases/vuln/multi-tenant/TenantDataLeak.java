/*
 * JSEF Benchmark 样本 — 多租户隔离失效：查询未带 tenant_id 过滤（VulnGym 子类 BL-MULTI-TENANT，CWE-639，L3）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"租户隔离语义"——按主键查询业务数据时未追加 tenant_id 条件，租户 A 可用自有 id
 * 读到租户 B 的同类记录（若 id 空间共享）。数据流干净，但缺失租户维度隔离。静态分析需在 findById 处
 * 识别"查询缺少 tenant 上下文过滤"。
 */
package com.jsef.benchmark.vuln;

public class TenantDataLeak {

    // 演示用：仓储
    static final class Record { final String id; final String tenantId; Record(String id, String t){ this.id=id; this.tenantId=t; } }
    interface Repo { Record findById(String id); }

    // 危险：按 id 取数据，未限定 tenant_id
    static Record get(Repo repo, String id) {
        // source：不可信 id（HTTP 参数，攻击者可控）
        // [CHECKPOINT id=JSEF-V1-TNT-001 cwe=639 level=L3 source=user-controlled id sink=repo.findById(id) (no tenant filter) expect=VULN]
        return repo.findById(id);   // 越权：跨租户读到他人记录
    }
}
