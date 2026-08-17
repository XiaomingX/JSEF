package com.jsef.benchmark.sec.gadgetmine;

/**
 * JSEF-Benchmark gadgetmine 族 — GmDepMissingSafe (JSEF-GM-004S, CWE-502, L2)
 * ============================================================================
 * 安全对照：对应 vuln 侧 GmDepMissing。此处演示"依赖存在时的正确处置"——通过显式
 * 白名单约束可实例化类型，即便某个第三方 gadget 依赖恰好存在于 classpath，也不因其
 * 存在而放开 AutoType 任意实例化；未知/未授权类一律拒绝。
 *
 * 与 vuln 侧区别：vuln 侧验证"依赖缺失 → 不可达 → SAFE"；本 sec 侧验证"依赖存在时仍
 * 以白名单收敛、不扩大攻击面"，同样预期 SAFE。用于计算 TN（真正例中的安全判定）。
 *
 * 安全底线声明：仅 localhost 演示语义，不引入真实 fastjson 依赖，不提供真实利用脚本。
 */
public class GmDepMissingSafe {

    /** 受信任类型白名单（演示用，仅 localhost 占位类型）。 */
    private static final java.util.Set<String> ALLOWLIST = java.util.Set.of(
            "com.jsef.benchmark.sec.gadgetmine.TrustedModel"
    );

    /**
     * 安全解析入口：以白名单收敛可实例化范围，不以"依赖是否存在"作为放行依据。
     */
    public static Object safeParse(String typeName) {
        // [CHECKPOINT id=JSEF-GM-004S cwe=502 level=L2 source=@type sink=allowlist (依赖存在仍收敛) expect=SAFE]
        if (!ALLOWLIST.contains(typeName)) {  // 白名单收敛：依赖存在也不放行未授权类
            throw new IllegalArgumentException("type not in allowlist: " + typeName);
        }
        return safeInstantiate(typeName);
    }

    private static Object safeInstantiate(String typeName) {
        System.out.println("[demo-only] safe-instantiating allowed type: " + typeName);
        return new Object();
    }
}
