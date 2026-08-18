// [VULN]
package com.jsef.benchmark.vuln.mspreachability;

/**
 * JSEF-Benchmark — 多步规划 P5：版本 + 配置双门控可达性（反序列化，L5）
 *
 * 设计意图：对抗「能定位不能证可达」「缺洞察跳跃」。sink（危险反序列化类型）仅在
 * 依赖版本 >= 2.0 且配置开关 enableUnsafeType 为 true 时可达；两个条件缺一即安全。
 * 正确规划末步必须产出「版本 + 配置双条件」的可达性证明，而非仅定位 sink 代码。
 *
 * ----------------------------------------------------------------------------
 * 长程任务子目标清单：
 *   ① 定位 sink 代码：UnsafeTypeDeserializer 的危险反序列化类型白名单缺失。
 *   ② 识别版本门控：依赖版本 >= 2.0 才启用动态类型解析。
 *   ③ 识别配置门控：enableUnsafeType=true 才放开危险类型。
 *   ④ 产出可达性证明：版本>=2.0 且配置开启时，不可信类型名可达危险反序列化 sink。
 * ----------------------------------------------------------------------------
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class VersionGatedReachability {

    private final String depVersion;        // 依赖版本，如 "2.3"
    private final boolean enableUnsafeType; // 配置开关

    public VersionGatedReachability(String depVersion, boolean enableUnsafeType) {
        this.depVersion = depVersion;
        this.enableUnsafeType = enableUnsafeType;
    }

    private boolean versionAllows() {
        // 语义等价：解析语义化版本号比较 >= 2.0
        String[] parts = depVersion.split("\\.");
        int major = Integer.parseInt(parts[0]);
        return major >= 2;
    }

    /**
     * sink：危险类型反序列化（语义等价：ObjectInputStream/readValue with unsafe type）。
     */
    public Object deserialize(String typeName, byte[] data) {
        // [CHECKPOINT id=JSEF-MSP-007 cwe=502 level=L5 source=attacker-controlled typeName sink=unsafe type deserialize expect=VULN trace=benchmark/cases/vuln/msp-reachability/VersionGatedReachability.java:43,benchmark/cases/vuln/msp-reachability/VersionGatedReachability.java:44]
        if (versionAllows() && enableUnsafeType) {
            return UnsafeTypeDeserializer.read(typeName, data); // 危险 sink（双条件满足可达）
        }
        return SafeTypeDeserializer.read(typeName, data); // 安全分支
    }

    static class UnsafeTypeDeserializer {
        static Object read(String typeName, byte[] data) {
            System.out.println("[abstract unsafe deserialize] " + typeName);
            return data;
        }
    }

    static class SafeTypeDeserializer {
        static Object read(String typeName, byte[] data) {
            return data; // 仅允许白名单类型
        }
    }
}
