// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 受保护资源（安全版）：依赖已验证的 principal。
 * 由于上游 JwtVerifierSafe 拒绝伪造 token，本端点仅在真实认证后可达。
 */
@RestController
public class AdminResourceSafe {

    private final RequestContextSafe requestContext;

    public AdminResourceSafe(RequestContextSafe requestContext) {
        this.requestContext = requestContext;
    }

    @GetMapping("/api/v1/admin/secrets")
    public String handle() {
        String principal = requestContext.getPrincipal();
        if (principal != null) {
            // principal 已来自签名校验通过的 token，伪造身份无法到达此处
            // [CHECKPOINT id=JSEF-BIZ5-287-004S cwe=287 level=L5 source=verified principal sink=admin resource access expect=SAFE trace=benchmark/cases/sec/bizlogic5/AuthFilterSafe.java:27,benchmark/cases/sec/bizlogic5/JwtVerifierSafe.java:20]
            return "secret-for:" + principal;
        }
        return "denied";
    }
}
