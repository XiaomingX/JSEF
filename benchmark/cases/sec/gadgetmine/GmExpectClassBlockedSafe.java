package com.jsef.benchmark.sec.gadgetmine;

/**
 * JSEF-Benchmark gadgetmine 族 — 安全对照（JSEF-GM-006S）
 * ============================================================
 * 对照维度 §一 (3)：1.2.68+ 后置接口封堵。
 * 安全要点：
 *   1) 使用 1.2.68+ 已封堵 expectClass 接口（ClassLoader/DataSource/RowSet）
 *      的任意来源均被拒绝；
 *   2) 或改用 AutoCloseable 安全变体（1.2.68+ 引入的可信接口），
 *      仅允许显式白名单内的可信类型，杜绝 JdbcRowSetImpl 直连链。
 *
 * 安全底线声明：仅 localhost 演示语义，不提供真实利用脚本。
 */
public class GmExpectClassBlockedSafe {

    /** 受信任类型白名单（演示用，仅 localhost 占位类型）。 */
    private static final java.util.Set<String> ALLOWLIST = java.util.Set.of(
            "com.jsef.benchmark.sec.gadgetmine.GmExpectClassBlockedSafe.SafeDto"
    );

    /**
     * 安全占位 DTO：实现 AutoCloseable 安全变体语义，且位于白名单。
     */
    public static class SafeDto implements AutoCloseable {
        @Override
        public void close() {
            // 安全资源释放（占位）
        }
    }

    /**
     * 安全解析入口：1.2.68+ 已封堵危险接口 + 白名单约束。
     */
    public static Object safeResolveViaExpectClass(String typeName) {
        // [CHECKPOINT id=JSEF-GM-006S cwe=502 level=L4 source=@type sink=expectClass interface block (1.2.68+) expect=SAFE]
        if (!ALLOWLIST.contains(typeName)) {   // 白名单校验：拒绝非受信类型
            throw new IllegalArgumentException("type not allowed: " + typeName);
        }
        System.out.println("[demo-only] safe-resolve allowed type (1.2.68+ block active): " + typeName);
        return new SafeDto();
    }
}
