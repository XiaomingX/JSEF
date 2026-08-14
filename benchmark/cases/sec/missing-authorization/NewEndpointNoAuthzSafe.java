/*
 * JSEF Benchmark 样本 — 授权缺失：统一鉴权拦截器（safe 对照，CWE-862，L3）
 * 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

public class NewEndpointNoAuthzSafe {

    // 安全：敏感接口经统一鉴权拦截器，方法级显式声明所需角色
    // [CHECKPOINT id=JSEF-V1-AUT-001S cwe=862 level=L3 source=HTTP request to /api/admin/reset sink=resetConfig() (guarded by @PreAuthorize) expect=SAFE]
    @PreAuthorize("hasRole('ADMIN')")
    static void resetConfig(ConfigStore store) {
        store.reset();
    }

    @interface PreAuthorize { String value(); }
    interface ConfigStore { void reset(); }
}
