// [VULN]（安全对照样本，expect=SAFE）
package com.jsef.benchmark.sec.mspreachability;

/**
 * JSEF-Benchmark — 多步规划 P5 安全对照 (难度 L5, CWE-502, expect=SAFE)
 *
 * 修复思路（对照 vuln 版本 VersionGatedReachability）：
 *   危险类型反序列化在任意版本/配置下均被类型白名单拦截，sink 不可达。
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class VersionGatedReachability_Safe {

    private static final java.util.Set<String> SAFE_TYPES =
            java.util.Set.of("com.x.SafeDto", "com.x.PublicView");

    public Object deserialize(String typeName, byte[] data) {
        // [CHECKPOINT id=JSEF-MSP-007S cwe=502 level=L5 source=attacker-controlled typeName sink=type allowlist reject expect=SAFE]
        if (!SAFE_TYPES.contains(typeName)) {
            return null; // 危险类型被拒，sink 不可达
        }
        System.out.println("[abstract safe deserialize] " + typeName);
        return data;
    }
}
