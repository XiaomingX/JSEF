// [VULN]
package com.jsef.benchmark.vuln;

/**
 * JSEF-Benchmark — Actuator 端点暴露 (CWE-749 不安全配置 / A05，难度 L3)
 *
 * 危险入口：application.properties 暴露所有 actuator 端点（含 env / heapdump）
 * 且未加认证，攻击者可读取环境变量（含密钥）与堆转储，造成信息泄露。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实信息提取脚本。
 */
public class ActuatorExposure {

    /**
     * 演示危险配置：暴露全部端点且无认证（实际写在 application.properties，
     * 此处以配置字符串表示被加载的危险设置）。
     */
    static String dangerousConfig() {
        // [CHECKPOINT id=JSEF-ACTUATOR-001 cwe=749 level=L3 source=exposed actuator endpoints sink=env/heapdump info leak expect=VULN]
        return "management.endpoints.web.exposure.include=*"; // 含 env, heapdump，无 spring-security
    }
}
