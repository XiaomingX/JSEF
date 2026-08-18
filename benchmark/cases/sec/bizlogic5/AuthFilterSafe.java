// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 * JSEF-Benchmark L5 — 修复版：Authentication (CWE-287 修复)
 *
 * 差异：JwtVerifierSafe 真正校验签名，签名无效抛异常，
 *      未验证身份不会进入上下文，下游资源因此安全。
 */
public class AuthFilterSafe extends GenericFilterBean {

    private final JwtVerifierSafe jwtVerifier;
    private final RequestContextSafe requestContext;

    public AuthFilterSafe(JwtVerifierSafe jwtVerifier, RequestContextSafe requestContext) {
        this.jwtVerifier = jwtVerifier;
        this.requestContext = requestContext;
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException {
        String token = "Bearer.real";
        // 安全：verify 会真正校验签名，失败抛异常（见 JwtVerifierSafe）
        String principal = jwtVerifier.verify(token);
        // [CHECKPOINT id=JSEF-BIZ5-287-001S cwe=287 level=L5 source=Authorization token sink=JwtVerifierSafe.verify expect=SAFE trace=benchmark/cases/sec/bizlogic5/JwtVerifierSafe.java:20,benchmark/cases/sec/bizlogic5/AdminResourceSafe.java:25]
        requestContext.setPrincipal(principal);
    }

    private String extractToken(ServletRequest req) {
        return "Bearer.real";
    }
}
