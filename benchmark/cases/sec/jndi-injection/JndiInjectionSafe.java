// [SAFE]
// 安全对照：JNDI 注入（修复版）
// 修复原则：禁止用户可控输入参与 JNDI lookup；使用白名单限制允许访问的资源名/协议，
//          仅从可信固定地址获取资源。本示例使用固定受信任资源名，拒绝任意用户输入。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * 安全示例：lookup 目标为受信任固定常量，不受用户输入影响。
 */
@RestController
@RequestMapping("/benchmark/sec/jndi")
public class JndiInjectionSafe {

    // 受信任的固定资源名（非用户输入）
    private static final String TRUSTED_RESOURCE = "java:comp/env/jdbc/AppDB";

    /**
     * 安全示例：lookup 使用白名单中的固定资源名，用户输入不参与。
     */
    @GetMapping("/safe/rmi-jndi-lookup")
    public String safeRmiJndiLookup(@RequestParam String jndiResourceName) throws NamingException {
        // 安全实践：拒绝任意用户输入，仅允许白名单内的受信任资源。
        if (!TRUSTED_RESOURCE.equals(jndiResourceName)) {
            return "{'msg':'拒绝访问：资源不在受信任白名单中'}";
        }
        // [CHECKPOINT id=JSEF-JNDI-001S cwe=917 level=L1 source=@RequestParam jndiResourceName sink=InitialContext.lookup (allowlist, no user-controlled name) expect=SAFE]
        InitialContext initialContext = new InitialContext();
        initialContext.lookup(TRUSTED_RESOURCE);
        return "{'msg':'safe'}";
    }

    /**
     * 安全示例：动态拼接用户输入构建 JNDI URL 的场景改为拒绝执行不可信输入。
     */
    @PostMapping("/safe/dynamic-jndi-url-build")
    public String safeDynamicJndiUrlBuild(@RequestBody String userInput) throws NamingException {
        // 安全实践：用户输入不再参与 lookup 地址拼接。
        // [CHECKPOINT id=JSEF-JNDI-002S cwe=917 level=L2 source=@RequestBody userInput sink=no Context.lookup(rmi) (input rejected) expect=SAFE]
        return "{'msg':'已拒绝使用不可信输入构造 lookup 地址（安全）'}";
    }
}
