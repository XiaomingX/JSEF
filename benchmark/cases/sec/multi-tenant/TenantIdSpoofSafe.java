/*
 * JSEF Benchmark 样本 — 多租户隔离失效：tenant 来自服务端上下文（safe 对照，CWE-285，L4）
 * 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

public class TenantIdSpoofSafe {

    static final class Req { String tenantId; }
    static final class Data { final String body; Data(String b){ this.body=b; } }
    interface Repo { Data findByTenant(String tenant); }

    // 安全：tenant 由服务端认证上下文决定，忽略客户端传入值
    static Data load(Repo repo, Req req, String serverTenant) {
        // [CHECKPOINT id=JSEF-V1-TNT-002S cwe=285 level=L4 source=req.tenantId (ignored) sink=repo.findByTenant(serverTenant) expect=SAFE]
        return repo.findByTenant(serverTenant);
    }
}
