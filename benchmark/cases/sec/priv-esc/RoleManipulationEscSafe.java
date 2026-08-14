/*
 * JSEF Benchmark 样本 — 权限提升精分：角色由服务端决定（safe 对照，CWE-269，L3）
 * 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

public class RoleManipulationEscSafe {

    static final class Profile { String username; String role; }

    // 安全：role 来自服务端会话，请求中的 role 字段被忽略
    static void update(Repo repo, Profile p, String serverRole) {
        // [CHECKPOINT id=JSEF-V1-PRV-001S cwe=269 level=L3 source=profile.role (ignored) sink=repo.save(p with serverRole) expect=SAFE]
        p.role = serverRole;
        repo.save(p);
    }

    interface Repo { void save(Profile p); }
}
