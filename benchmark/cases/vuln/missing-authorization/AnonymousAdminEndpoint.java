/*
 * JSEF Benchmark 样本 — 授权缺失：管理端点匿名可达（VulnGym 子类 BL-AUTHZ-MISSING，CWE-862，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"授权缺失语义"——管理端点既未要求认证也未要求授权，匿名请求即可到达敏感操作。
 * 数据流干净，但认证/授权前置整体缺失。静态分析需在端点入口识别"匿名可调用管理动作"。
 */
package com.jsef.benchmark.vuln;

public class AnonymousAdminEndpoint {

    // 危险：管理端点无认证/授权，匿名可达
    // [CHECKPOINT id=JSEF-V1-AUT-002 cwe=862 level=L4 source=anonymous request to /admin/export sink=exportSecrets() (no authn/authz) expect=VULN]
    static String exportSecrets(SecretStore store) {
        return store.exportAll();   // 越权：匿名导出全部敏感配置
    }

    interface SecretStore { String exportAll(); }
}
