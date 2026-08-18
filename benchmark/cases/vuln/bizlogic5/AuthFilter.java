// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 * JSEF-Benchmark L5 — 业务逻辑漏洞：Authentication Bypass (CWE-287)
 *
 * 跨中间件认证绕过：认证判断分散在过滤器（中间件）与受保护资源之间，
 * 信任边界被破坏——资源端点只检查"上下文是否含有 principal"，但 principal
 * 可由未经验证的 token（甚至攻击者伪造/空 token）填充。
 *
 * 区分度来源（L5 跨文件）：
 *   信任建立点在 AuthFilter（source: Authorization 头），但真实签名校验被跳过，
 *   跨 3 个编译单元到达受保护资源 sink：
 *     AuthFilter (source: token) -> JwtVerifier.verify(token)  [签名校验被绕过]
 *       -> RequestContext.setPrincipal(name)                    [注入未验证身份]
 *       -> AdminResource.handle()                               [sink: 仅检查 principal!=null]
 *
 * VulnGym 范式对齐：BL-AUTH-BYPASS（认证绕过）—— 需理解中间件信任边界。
 */
public class AuthFilter extends GenericFilterBean {

    private final JwtVerifier jwtVerifier;
    private final RequestContext requestContext;

    public AuthFilter(JwtVerifier jwtVerifier, RequestContext requestContext) {
        this.jwtVerifier = jwtVerifier;
        this.requestContext = requestContext;
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException {
        String token = extractToken(req); // 来自 Authorization 头（source）
        // 缺陷：verify 实际跳过了签名校验（见 JwtVerifier），但调用方信任其返回
        String principal = jwtVerifier.verify(token);
        // [CHECKPOINT id=JSEF-BIZ5-287-001 cwe=287 level=L5 source=Authorization token sink=JwtVerifier.verify expect=VULN trace=benchmark/cases/vuln/bizlogic5/JwtVerifier.java:16,benchmark/cases/vuln/bizlogic5/RequestContext.java:14,benchmark/cases/vuln/bizlogic5/AdminResource.java:27]
        requestContext.setPrincipal(principal); // 未验证身份被注入上下文
        // ... chain.doFilter(req, res);
    }

    private String extractToken(ServletRequest req) {
        // 语义等价：((HttpServletRequest) req).getHeader("Authorization")
        return "Bearer.unverified";
    }
}
