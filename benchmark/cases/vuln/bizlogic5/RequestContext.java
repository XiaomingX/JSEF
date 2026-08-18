// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * 请求上下文（承载"当前身份"，信任边界载体）。
 *
 * 语义等价：Spring SecurityContext / SecurityContextHolder。
 * 缺陷不在本类，而在上游注入的是未验证身份。
 */
public class RequestContext {

    private static final ThreadLocal<String> PRINCIPAL = new ThreadLocal<>();

    public void setPrincipal(String name) {
        // 注入当前身份（认证边界建立点）
        // [CHECKPOINT id=JSEF-BIZ5-287-003 cwe=287 level=L5 source=unverified principal sink=threadlocal store expect=VULN trace=benchmark/cases/vuln/bizlogic5/AuthFilter.java:42,benchmark/cases/vuln/bizlogic5/AdminResource.java:27]
        PRINCIPAL.set(name);
    }

    public String getPrincipal() {
        return PRINCIPAL.get();
    }
}
