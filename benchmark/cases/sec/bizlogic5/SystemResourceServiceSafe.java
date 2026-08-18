// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * 系统资源服务（安全版，sink 受正确授权保护）。
 */
public class SystemResourceServiceSafe {

    public String purgeCache() {
        // 语义等价：cacheManager.getCache("system").clear();
        // 此路径仅在 ADMIN 授权通过后到达（见 AdminControllerSafe）
        System.out.println("[system-cache-purge][authorized] 高危管理操作被执行");
        return "purged";
    }
}
