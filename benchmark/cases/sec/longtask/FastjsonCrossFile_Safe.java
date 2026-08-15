package com.jsef.benchmark.vuln.longtask;

/**
 * JSEF-Benchmark L4（长程任务 A 组）— 安全对照（sec）
 * ============================================================
 * 修复方案：对应 vuln 三文件（A/B/C）的 fastjson AutoType 跨类触发。
 * 安全要点：
 *   1) 关闭 AutoType（不按攻击者控制的 `@type`/类名实例化任意类）；
 *   2) 使用类型白名单（allowlist）显式约束可反序列化的类名；
 *   3) 任何不在白名单中的类型名直接拒绝，绝不实例化。
 *
 * 与 vuln 的区别：vuln 在文件 C 对不可信 typeName 直接实例化；
 * 本文件在实例化前做 allowlist 校验，阻断 gadget chain 触发。
 *
 * 安全底线声明：仅 localhost 演示语义，不提供真实利用脚本。
 */
public class FastjsonCrossFile_Safe {

    /** 受信任类型白名单（演示用，仅 localhost 占位类型）。 */
    private static final java.util.Set<String> ALLOWLIST = java.util.Set.of(
            "com.example.LocalModel",
            "com.example.SafeDto"
    );

    /**
     * 安全处理入口：接收不可信类型名，先做白名单校验。
     */
    public static Object safeProcess(String untrustedTypeName) {
        // [CHECKPOINT id=JSEF-LT-001S cwe=502 level=L4 source=untrustedJson sink=allowlist check expect=SAFE]
        if (!ALLOWLIST.contains(untrustedTypeName)) {   // 安全处理行：allowlist 校验
            throw new IllegalArgumentException("type not allowed: " + untrustedTypeName);
        }
        return safeInstantiate(untrustedTypeName);
    }

    /**
     * 仅在白名单通过后实例化，杜绝 AutoType 任意类实例化（CWE-502 修复）。
     */
    private static Object safeInstantiate(String typeName) {
        System.out.println("[demo-only] safe-instantiating allowed type: " + typeName);
        return new Object();
    }
}
