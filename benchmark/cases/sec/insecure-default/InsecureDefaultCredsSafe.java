/*
 * JSEF Benchmark 样本 — 不安全默认配置：禁用默认账户（safe 对照，CWE-1188，L2）
 * 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

public class InsecureDefaultCredsSafe {

    // 安全：不创建默认账户，强制首次部署由运维注入强凭证
    static void seedDefaultUser(UserStore store) {
        // [CHECKPOINT id=JSEF-V1-DEF-001S cwe=1188 level=L2 source=hardcoded default (none) sink=store.createUser (disabled by default) expect=SAFE]
        if (Boolean.getBoolean("app.allow.default.user")) {
            throw new IllegalStateException("default user must be disabled in production");
        }
    }

    interface UserStore { void createUser(String u, String p); }
}
