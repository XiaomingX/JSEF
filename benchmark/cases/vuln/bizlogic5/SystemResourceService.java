// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * 系统资源服务（危险 sink 落点）。
 *
 * 语义等价：缓存/配置清理等高危管理操作（如 CacheManager.clear()、
 * 或删除系统级数据）。普通已登录用户不应触达。
 */
public class SystemResourceService {

    /** 危险终点：高危管理操作，无二次授权保护。 */
    public String purgeCache() {
        // 语义等价：cacheManager.getCache("system").clear();
        // [CHECKPOINT id=JSEF-BIZ5-863-003 cwe=863 level=L5 source=unprivileged-but-authenticated caller sink=cache purge operation expect=VULN trace=benchmark/cases/vuln/bizlogic5/AdminController.java:34,benchmark/cases/vuln/bizlogic5/InsecureAuthzService.java:21]
        System.out.println("[system-cache-purge] 高危管理操作被执行");
        return "purged";
    }
}
