package com.jsef.benchmark.sec.gadgetmine;

/**
 * JSEF-Benchmark gadgetmine 族 — GmDenyListBlockedSafe (JSEF-GM-003S, CWE-502, L3)
 * ============================================================================
 * 安全对照：对应 vuln 侧 GmDenyListBlocked。此处演示"deny 名单 + allowlist 双重生效"
 * 的正确处置。即便 autoTypeSupport 开启，deny 名单优先拦截已知危险类，allowlist 进一步
 * 收紧可实例化范围，确保任何危险或未知类都不会被实例化。
 *
 * 与 vuln 侧区别：vuln 侧仅靠 deny 拦截（已判 SAFE）；本 sec 侧展示更稳妥的"deny +
 * allowlist"组合防护，作为 deny 生效场景的安全对照参照，预期同样 SAFE。
 *
 * 安全底线声明：仅 localhost 演示语义，不引入真实 fastjson 依赖，不提供真实利用脚本。
 */
public class GmDenyListBlockedSafe {

    /** 受信任类型白名单（演示用，仅 localhost 占位类型）。 */
    private static final java.util.Set<String> ALLOWLIST = java.util.Set.of(
            "com.jsef.benchmark.sec.gadgetmine.TrustedModel"
    );

    /**
     * 安全解析入口：先查 deny 名单，再查 allowlist，二者皆通过才实例化。
     */
    public static Object safeParse(String typeName) {
        // ① deny 名单优先（与 vuln 侧同语义，命中即拦）
        if (isDenyListed(typeName)) {
            // [CHECKPOINT id=JSEF-GM-003S cwe=502 level=L3 source=@type sink=deny/allowlist block expect=SAFE]
            throw new IllegalArgumentException("fastjson deny list blocked: " + typeName);  // deny 拦截
        }
        // ② allowlist 收紧可实例化范围
        if (!ALLOWLIST.contains(typeName)) {
            throw new IllegalArgumentException("type not in allowlist: " + typeName);
        }
        return safeInstantiate(typeName);
    }

    private static Object safeInstantiate(String typeName) {
        System.out.println("[demo-only] safe-instantiating allowed type: " + typeName);
        return new Object();
    }

    /** 模拟 fastjson 内置 denyHashCodes 前缀匹配（localhost 演示语义）。 */
    private static boolean isDenyListed(String typeName) {
        return typeName != null
                && (typeName.startsWith("org.apache.commons.collections.functors.")
                    || typeName.startsWith("com.sun.")
                    || typeName.startsWith("org.apache.xalan."));
    }
}
