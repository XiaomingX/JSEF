package com.jsef.benchmark.vendor.components;

/**
 * JSEF Benchmark — A06 易受攻击组件（CWE-1104，L2）
 *
 * 场景：pom.xml 直接引入了已知存在远程代码执行漏洞的 log4j-core 2.14.1
 * （CVE-2021-44228，Log4Shell）。该版本在记录含 ${jndi:...} 的日志时
 * 会发起 JNDI 查找，攻击者可借不可信输入触发 RCE。
 *
 * 为何危险：依赖版本本身是攻击者可控的"软供应链"入口，一旦含已知 CVE 的
 * 组件被打入制品，整条链路的可信性归零，且常被 SCA/依赖扫描忽略。
 *
 * 安全底线：仅 localhost 演示语义，不写真实 JNDI/LDAP 利用脚本。
 *
 * 本文件采用"单文件双 checkpoint"写法：VULN 行声明危险版本常量，
 * SAFE 行声明已修复版本常量（2.17.1）。配套 pom 片段见 pom_log4j.xml。
 */
public class VulnerableDepLog4j {

    /**
     * VULN：引入存在 CVE-2021-44228 的 log4j-core 2.14.1。
     */
    // [CHECKPOINT id=JSEF-A06-001 cwe=1104 level=L2 source=pom.xml / build config sink=dependency:org.apache.logging.log4j:log4j-core:2.14.1 (CVE-2021-44228) expect=VULN]
    static final String LOG4J_CORE_VERSION = "2.14.1";

    /**
     * SAFE：升级到已修复的 log4j-core 2.17.1。
     */
    // [CHECKPOINT id=JSEF-A06-001S cwe=1104 level=L2 source=pom.xml / build config sink=dependency:org.apache.logging.log4j:log4j-core:2.17.1 (CVE-2021-44228 fixed) expect=SAFE]
    static final String LOG4J_CORE_VERSION_SAFE = "2.17.1";

    public static void main(String[] args) {
        System.out.println("[demo] log4j-core resolved version = " + LOG4J_CORE_VERSION
                + " (should be 2.17.1 in production)");
    }
}
