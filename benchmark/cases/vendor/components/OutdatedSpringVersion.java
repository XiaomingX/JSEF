package com.jsef.benchmark.vendor.components;

/**
 * JSEF Benchmark — A06 易受攻击组件（CWE-937，L2）
 *
 * 场景：使用 Spring Framework 5.2.x 基线版本，该分支存在若干已知 CVE
 * （如 CVE-2022-22965 Spring4Shell 在 5.2.x 部分版本未修复、CVE-2022-22950
 * SpEL DoS 等）。停留在过时主版本意味着已知漏洞长期敞口。
 *
 * 为何危险：框架主版本不随安全补丁升级，等同于"默认接受"所有该分支已披露
 * 但未修复的 CVE，是组织级供应链风险。
 *
 * 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 单文件双 checkpoint：VULN 行声明 5.2.x，SAFE 行声明 5.3.x+（已含修复）。
 * 配套 pom 片段见 pom_spring.xml。
 */
public class OutdatedSpringVersion {

    /**
     * VULN：锁定易受攻击的 Spring 5.2.x 基线。
     */
    // [CHECKPOINT id=JSEF-A06-003 cwe=937 level=L2 source=pom.xml / build config sink=dependency:org.springframework:spring-core:5.2.x (known CVEs) expect=VULN]
    static final String SPRING_VERSION = "5.2.20.RELEASE";

    /**
     * SAFE：升级到已修复的 5.3.x+ 基线。
     */
    // [CHECKPOINT id=JSEF-A06-003S cwe=937 level=L2 source=pom.xml / build config sink=dependency:org.springframework:spring-core:5.3.x+ (CVEs fixed) expect=SAFE]
    static final String SPRING_VERSION_SAFE = "5.3.39.RELEASE";

    public static void main(String[] args) {
        System.out.println("[demo] spring resolved version = " + SPRING_VERSION
                + " (should be 5.3.x+ in production)");
    }
}
