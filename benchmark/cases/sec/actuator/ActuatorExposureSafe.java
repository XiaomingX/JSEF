// [SAFE]
package com.jsef.benchmark.sec;

/**
 * JSEF-Benchmark — Actuator 安全对照 (CWE-749 / A05，难度 L3)
 *
 * 修复：仅暴露必要端点（health, info），并启用 spring-security 对 actuator
 * 加认证，杜绝 env / heapdump 未授权访问。
 */
public class ActuatorExposureSafe {

    /**
     * 安全配置：限定暴露端点 + 需认证。
     */
    static String safeConfig() {
        // [CHECKPOINT id=JSEF-ACTUATOR-001S cwe=749 level=L3 source=actuator exposure config sink=limited endpoints + auth expect=SAFE]
        return "management.endpoints.web.exposure.include=health,info"; // 配合 spring-security 认证
    }
}
