package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L2 — LDAP 过滤器黑名单净化存在漏洞
 *
 * 难度：L2（多跳但无断点）。手工构造 LDAP 搜索过滤器字符串，仅用黑名单 sanitize
 * 把单引号 ' 替换为空，却遗漏了 * ( ) \ 0 等 LDAP 过滤器元字符。攻击者可注入
 * LDAP 搜索过滤器（如 * 通配、)( 改写过滤器结构），绕过鉴权或拖库。
 *
 * CWE-90 (LDAP Injection)。安全底线：仅 localhost 演示语义，不引入真实 LDAP 库。
 *
 * 修复要点（对照 LdapBlacklistHoleSafe.java）：使用 RFC 4515 编码或白名单字符校验。
 *
 * 占位说明：LdapSearchStub 为教学占位，search(filter) 仅 localhost 打印，注释声明
 * 语义等价 ctx.search —— 被测工具/模型应按注释声明的语义报告漏洞，而非逐字执行桩体。
 */
public class LdapBlacklistHoleVuln {

    /**
     * 用用户输入拼 LDAP 过滤器并“净化”后检索。
     *
     * @param user 用户可控的 cn 值
     */
    public void find(String user) {
        String filter = "(cn=" + user + ")";          // 手工拼接过滤器
        String safe = sanitize(filter);               // 黑名单只剥掉 '
        // [CHECKPOINT id=JSEF-LDAPH-001 cwe=90 level=L2 source=user input filter sink=sanitize only strips ' (ldap injection) expect=VULN]
        LdapSearchStub.search(safe);                  // *()\0 等仍可注入 LDAP 过滤器
    }

    // 缺陷净化：黑名单只 replace 单引号，漏掉 * ( ) \ 0 等元字符
    static String sanitize(String s) {
        return s.replace("'", "");
    }

    // 抽象 sink：语义等价 ctx.search(base, filter, ctrl)，仅 localhost 打印
    static class LdapSearchStub {
        static void search(String filter) {
            System.out.println("[ldap-search] " + filter);
        }
    }

    public static void main(String[] args) {
        new LdapBlacklistHoleVuln().find("*)(uid=*");
    }
}
