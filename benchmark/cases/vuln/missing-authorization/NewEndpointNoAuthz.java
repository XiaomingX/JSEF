/*
 * JSEF Benchmark 样本 — 授权缺失：新增接口漏加 @PreAuthorize（VulnGym 子类 BL-AUTHZ-MISSING，CWE-862，L3）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"授权缺失语义"——新增业务接口忘记加方法级鉴权注解，任何已登录（甚至匿名）用户都能调用。
 * 数据流干净，但缺失统一的授权前置。静态分析需在方法入口识别"敏感操作无 @PreAuthorize/hasRole 约束"。
 */
package com.jsef.benchmark.vuln;

public class NewEndpointNoAuthz {

    // 危险：敏感接口未加任何授权注解
    // [CHECKPOINT id=JSEF-V1-AUT-001 cwe=862 level=L3 source=HTTP request to /api/admin/reset sink=resetConfig() (no @PreAuthorize) expect=VULN]
    static void resetConfig(ConfigStore store) {
        store.reset();   // 越权：任意登录用户可重置配置
    }

    interface ConfigStore { void reset(); }
}
