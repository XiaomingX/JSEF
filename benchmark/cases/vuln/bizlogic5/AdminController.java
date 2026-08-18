// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 — 业务逻辑漏洞：Incorrect Authorization (CWE-863)
 *
 * 区分度来源（为什么要 L5）：
 *   纯语法 SAST 看到入口处调用了 `authzService.isAuthenticated(token)` 并返回 true，
 *   极易误判为"已授权"而放行；但真正的危险在于授权判断**只校验了"是否登录"**，
 *   漏掉了"是否具备 ADMIN 角色"这一业务授权语义。污点跨 3 个编译单元：
 *     AdminController (source: 外部 token 头)
 *       -> InsecureAuthzService.isAuthenticated(token)  [只验登录态，不验角色]
 *       -> SystemResourceService.purgeCache()           [sink: 高危管理操作]
 *
 * VulnGym 范式对齐：BL-AUTHZ-MISSING（缺失授权）—— 真实仓库级业务逻辑缺陷，
 * 无法用单文件 snippet 表达，需要跨模块语义推理。
 *
 * 安全底线：localhost 教学语义，不提供真实提权利用脚本。
 */
@RestController
public class AdminController {

    private final InsecureAuthzService authzService;
    private final SystemResourceService resourceService;

    public AdminController(InsecureAuthzService authzService,
                            SystemResourceService resourceService) {
        this.authzService = authzService;
        this.resourceService = resourceService;
    }

    @DeleteMapping("/api/v1/admin/cache")
    public String purgeCache(@RequestHeader("X-Auth-Token") String token) {
        // 入口：token 来自外部请求头（source）
        // 错误授权：仅校验"是否已登录"，未校验角色是否为 ADMIN
        if (authzService.isAuthenticated(token)) {
            // [CHECKPOINT id=JSEF-BIZ5-863-001 cwe=863 level=L5 source=X-Auth-Token header (authenticated but not authorized) sink=SystemResourceService.purgeCache expect=VULN trace=benchmark/cases/vuln/bizlogic5/InsecureAuthzService.java:21,benchmark/cases/vuln/bizlogic5/SystemResourceService.java:15]
            return resourceService.purgeCache(); // 任意已登录用户均可触发高危操作
        }
        return "denied";
    }
}
