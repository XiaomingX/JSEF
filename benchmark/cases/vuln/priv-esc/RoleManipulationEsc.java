/*
 * JSEF Benchmark 样本 — 权限提升精分：修改 role 字段提权（VulnGym 子类 BL-PRIV-ESC，CWE-269，L3）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"角色来源语义"——用户提交的对象（如 profile）直接绑定 role 字段并持久化，
 * 服务端未区分"客户端字段"与"服务端权威角色"。数据流干净，但角色可被客户端写入。静态分析需在
 * save(role) 处识别"role 来自不可信绑定"。
 */
package com.jsef.benchmark.vuln;

public class RoleManipulationEsc {

    // 演示用：用户对象
    static final class Profile { String username; String role; }

    // 危险：直接把请求里的 role 存库
    static void update(Repo repo, Profile p) {
        // source：不可信 p.role（HTTP 绑定，可改为 admin）
        // [CHECKPOINT id=JSEF-V1-PRV-001 cwe=269 level=L3 source=profile.role (client-bound) sink=repo.save(p) (role persisted) expect=VULN]
        repo.save(p);   // 越权：把自身 role 改为 admin
    }

    interface Repo { void save(Profile p); }
}
