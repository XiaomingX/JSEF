// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 — 修复版：Correct Authorization (CWE-863 修复)
 *
 * 与 AdminController（vuln）同结构，差异仅在授权判断：
 *   入口调用 authzService.hasRole(token, "ADMIN") —— 既验登录态，也验角色。
 *   普通已登录用户（非 ADMIN）将被拒绝，无法触达 purgeCache。
 *
 * 评分约定（AGENTS.md）：SAFE 侧按实现判定。本实现真实实现了角色级授权。
 */
@RestController
public class AdminControllerSafe {

    private final SecureAuthzService authzService;
    private final SystemResourceServiceSafe resourceService;

    public AdminControllerSafe(SecureAuthzService authzService,
                               SystemResourceServiceSafe resourceService) {
        this.authzService = authzService;
        this.resourceService = resourceService;
    }

    @DeleteMapping("/api/v1/admin/cache")
    public String purgeCache(@RequestHeader("X-Auth-Token") String token) {
        // 安全：校验"是否已登录" + "是否持有 ADMIN 角色"
        if (authzService.hasRole(token, "ADMIN")) {
            // [CHECKPOINT id=JSEF-BIZ5-863-001S cwe=863 level=L5 source=X-Auth-Token header sink=SystemResourceService.purgeCache expect=SAFE trace=benchmark/cases/sec/bizlogic5/SecureAuthzService.java:19,benchmark/cases/sec/bizlogic5/SystemResourceServiceSafe.java:9]
            return resourceService.purgeCache(); // 仅 ADMIN 可触发
        }
        return "denied";
    }
}
