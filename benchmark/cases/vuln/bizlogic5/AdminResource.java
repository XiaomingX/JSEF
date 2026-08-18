// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 受保护资源（危险 sink：仅检查 principal 非空，不二次验证）。
 *
 * 语义等价：@GetMapping("/admin") 管理端点。
 * 缺陷：handle 只判断 getPrincipal() != null，而 principal 可由伪造 token
 *      经 AuthFilter 注入，导致认证被绕过（CWE-287）。
 */
@RestController
public class AdminResource {

    private final RequestContext requestContext;

    public AdminResource(RequestContext requestContext) {
        this.requestContext = requestContext;
    }

    @GetMapping("/api/v1/admin/secrets")
    public String handle() {
        String principal = requestContext.getPrincipal();
        if (principal != null) { // 仅检查非空，不验证真实性
            // [CHECKPOINT id=JSEF-BIZ5-287-004 cwe=287 level=L5 source=unverified principal sink=admin resource access expect=VULN trace=benchmark/cases/vuln/bizlogic5/AuthFilter.java:42,benchmark/cases/vuln/bizlogic5/JwtVerifier.java:16,benchmark/cases/vuln/bizlogic5/RequestContext.java:14]
            return "secret-for:" + principal; // 伪造身份可触达
        }
        return "denied";
    }
}
