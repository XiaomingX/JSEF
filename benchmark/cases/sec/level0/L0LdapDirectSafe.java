package com.jsef.benchmark.sec;

import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

/**
 * JSEF-Benchmark L0 — L0LdapDirect 安全对照（SAFE 混淆样本）
 *
 * 安全做法：对不可信输入做 LDAP 过滤器字符转义（转义 * ( ) \ 等），
 * 防止注入；或使用参数化目录查询。用于计算 TN / FP。
 *
 * CWE-90 LDAP Injection。
 */
public class L0LdapDirectSafe {

    /**
     * 安全查询：对输入做 LDAP 转义后再拼入过滤器。
     *
     * @param userInput 不可信输入
     */
    public void run(Hashtable<String, Object> env, String userInput) throws Exception {
        DirContext ctx = new InitialDirContext(env);
        String safe = escapeLdap(userInput);
        // [CHECKPOINT id=JSEF-L0-LDAP-001S cwe=90 level=L0 source=userInput sink=InitialDirContext.search expect=SAFE]
        ctx.search("ou=people", "(uid=" + safe + ")", null, null);
    }

    private static String escapeLdap(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '*' || c == '(' || c == ')' || c == '\\' || c == '\0') {
                sb.append('\\').append(c);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        new L0LdapDirectSafe().run(new Hashtable<>(), "localhost-demo");
    }
}
