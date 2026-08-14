/*
 * JSEF Benchmark 样本 — 不安全默认配置：默认账户/密码启用（VulnGym 子类 BL-INSECURE-DEFAULT，CWE-1188，L2）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"默认配置语义"——系统初始化时启用众所周知的默认账户/密码且未强制首次登录修改。
 * 数据流干净，但默认凭据构成认证前置风险。静态分析需在 seedDefaultUser() 处识别"启用已知默认凭证"。
 */
package com.jsef.benchmark.vuln;

public class InsecureDefaultCreds {

    // 危险：初始化时写入已知默认账户
    static void seedDefaultUser(UserStore store) {
        // source：硬编码默认凭据（构建/启动配置）
        // [CHECKPOINT id=JSEF-V1-DEF-001 cwe=1188 level=L2 source=hardcoded default admin/password sink=store.createUser(admin, "admin") expect=VULN]
        store.createUser("admin", "admin");   // 不安全默认：可被猜解登录
    }

    interface UserStore { void createUser(String u, String p); }
}
