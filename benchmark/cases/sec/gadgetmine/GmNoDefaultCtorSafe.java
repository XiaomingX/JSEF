package com.jsef.benchmark.sec.gadgetmine;

/**
 * JSEF-Benchmark gadgetmine 族 — 安全对照（JSEF-GM-005S）
 * ============================================================
 * 对照维度 §一 (7)：可实例化。
 * 安全要点：目标类提供 public 无参构造（可被正常实例化），
 *   且通过类名白名单（allowlist）约束可反序列化的类型，
 *   杜绝 AutoType 任意类实例化（CWE-502 修复）。
 *
 * 安全底线声明：仅 localhost 演示语义，不提供真实利用脚本。
 */
public class GmNoDefaultCtorSafe {

    /** 受信任类型白名单（演示用，仅 localhost 占位类型）。 */
    private static final java.util.Set<String> ALLOWLIST = java.util.Set.of(
            "com.jsef.benchmark.sec.gadgetmine.GmNoDefaultCtorSafe.SafeModel"
    );

    /**
     * 安全占位模型：含 public 无参构造，可被正常实例化。
     */
    public static class SafeModel {
        // public 无参构造：实例化入口可用
        public SafeModel() {
            // 安全默认构造
        }
    }

    /**
     * 安全解析入口：先做白名单校验，仅允许受信类型。
     */
    public static Object safeResolveViaType(String typeName) {
        // [CHECKPOINT id=JSEF-GM-005S cwe=502 level=L2 source=@type sink=allowlist check expect=SAFE]
        if (!ALLOWLIST.contains(typeName)) {   // 白名单校验：阻断任意类实例化
            throw new IllegalArgumentException("type not allowed: " + typeName);
        }
        System.out.println("[demo-only] safe-instantiate allowed type: " + typeName);
        return new SafeModel();
    }
}
