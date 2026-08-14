package com.jsef.benchmark.vuln;

import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

/**
 * JSEF-Benchmark L0 — 基线（LDAP 注入，单跳直连）
 *
 * 难度：L0（基线）。source 直接传入 sink，无中间变量。
 * 用于校准 TP 基线与定位精度（CAP-03 入门级）。
 *
 * CWE-90 LDAP Injection。
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class L0LdapDirect {

    /**
     * 单跳：不可信入参直接拼入 LDAP 查询过滤器（sink）。
     *
     * @param userInput 不可信输入（类比 @RequestParam user）
     */
    public void run(Hashtable<String, Object> env, String userInput) throws Exception {
        DirContext ctx = new InitialDirContext(env);
        // [CHECKPOINT id=JSEF-L0-LDAP-001 cwe=90 level=L0 source=userInput sink=InitialDirContext.search expect=VULN]
        ctx.search("ou=people", "(uid=" + userInput + ")", null, null);
    }

    public static void main(String[] args) {
        System.out.println("demo: search (uid=localhost-demo)");
    }
}
