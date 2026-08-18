// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * 请求上下文（安全版）。评分约定：SAFE 侧按实现判定。
 * 仅承载来自已验证身份的 principal（上游 JwtVerifierSafe 已拦截伪造）。
 */
public class RequestContextSafe {

    private static final ThreadLocal<String> PRINCIPAL = new ThreadLocal<>();

    public void setPrincipal(String name) {
        PRINCIPAL.set(name);
    }

    public String getPrincipal() {
        return PRINCIPAL.get();
    }
}
