// [VULN]（安全对照样本，expect=SAFE）
package com.jsef.benchmark.sec.mspreachability;

/**
 * JSEF-Benchmark — 多步规划 P5 安全对照 (难度 L5, CWE-862, expect=SAFE)
 *
 * 修复思路（对照 vuln 版本 ConditionalAuthzBypass）：
 *   无论维护模式 / 时序窗口，角色校验始终生效，低权限调用方不可达 adminResource。
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class ConditionalAuthzBypass_Safe {

    public Object adminResource(String callerRole) {
        // [CHECKPOINT id=JSEF-MSP-008S cwe=862 level=L5 source=low-privilege callerRole sink=role check reject expect=SAFE]
        if (!"ADMIN".equals(callerRole)) {
            return "DENIED"; // 角色校验始终生效，sink 不可达
        }
        System.out.println("[abstract admin action] executed");
        return "OK";
    }
}
