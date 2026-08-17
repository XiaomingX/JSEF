package com.jsef.benchmark.sec.gadgetmine;

import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * JSEF-Benchmark gadgetmine 族 — fastjson 缓存绕过（sec 安全对照）
 * ============================================================
 * 安全对照 id：JSEF-GM-002S（对应 vuln JSEF-GM-002）。
 *
 * 安全要点（阻断条件，满足任一即安全）：
 *   - 版本已修补：fastjson 1.2.68+ 已修复 java.lang.Class + $ref 的缓存绕过，
 *     TypeUtils 缓存不再接受攻击者的类注入，黑名单不可被"复活"；
 *   - 或显式拒绝：安全配置下禁止 @type=java.lang.Class 的缓存写路径，
 *     并禁用 $ref 跨条目引用，从入口阻断 cache bypass gadget chain。
 *
 * 预期结果：SAFE（CWE-502 被阻断）。
 * 依据：在 1.2.68+ 或显式拒绝配置下，java.lang.Class 无法将恶意类写入缓存，
 *   $ref 复活路径失效，因此后续 setter 驱动的 InitialContext.lookup 永不被触发。
 *
 * 安全底线声明：仅 localhost 演示语义。不引用真实 com.alibaba.fastjson 依赖，
 * 仅以占位逻辑表达"缓存绕过路径被修补/拒绝"的安全状态。
 */
public class GmCacheBypassSafe {

    /**
     * 安全入口：拒绝 java.lang.Class 缓存写路径，并禁用 $ref 复活。
     * 任何命中缓存绕过尝试的类型名直接拒绝。
     */
    public static void safeDemo(String typeName, String dataSourceName) {
        // [CHECKPOINT id=JSEF-GM-002S cwe=502 level=L4 source=@type=java.lang.Class + $ref sink=cache-bypass patched / deny expect=SAFE]
        if ("java.lang.Class".equals(typeName)) { // 安全处理行：拒绝缓存写路径，阻断 cache bypass
            throw new IllegalArgumentException("java.lang.Class cache path denied (patched in 1.2.68+)");
        }
        // 即便通过，亦不触发 lookup：安全实现中 setter 不再驱动 JNDI sink
        SafeRowSet stub = new SafeRowSet();
        stub.setDataSourceNameSafe(dataSourceName);
    }

    /**
     * 安全占位类：setter 仅本地存储，不触发任何 lookup / 网络回连。
     */
    public static class SafeRowSet {
        private String dataSourceName;
        public void setDataSourceNameSafe(String dataSourceName) {
            this.dataSourceName = dataSourceName; // 安全：仅本地字段，无 sink 调用
        }
    }
}
