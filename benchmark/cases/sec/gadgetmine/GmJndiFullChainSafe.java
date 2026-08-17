package com.jsef.benchmark.sec.gadgetmine;

import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * JSEF-Benchmark gadgetmine 族 — JndiRowSetImpl 风格 JNDI 链（sec 安全对照）
 * ============================================================
 * 安全对照 id：JSEF-GM-001S（对应 vuln JSEF-GM-001）。
 *
 * 安全要点（阻断条件，满足任一即安全）：
 *   - autoTypeSupport=false：@type 不被 fastjson 解析，占位类不会被实例化，
 *     setDataSourceName 不会被调用，lookup 永不被触发；
 *   - 或 deny 名单包含该类 / 类型白名单不含该类：实例化阶段被直接拒绝。
 *
 * 预期结果：SAFE（CWE-502 被阻断）。
 * 依据：在 autotype 关闭或 deny 名单命中下，fastjson 不会按 @type 实例化
 *   JndiRowSetStub，因此不可信 dataSourceName 无法进入 setter，危险 sink
 *   InitialContext.lookup 不会被执行。
 *
 * 安全底线声明：仅 localhost 演示语义。不引用真实 com.alibaba.fastjson 依赖，
 * 仅以占位逻辑表达"类型过闸被关闭/拒绝"的安全状态。
 */
public class GmJndiFullChainSafe {

    /** 受信任类型白名单（演示用）。deny 语义可由"不在白名单即拒绝"等价表达。 */
    private static final java.util.Set<String> ALLOWLIST = java.util.Set.of(
            "com.example.LocalModel"
    );

    /**
     * 安全入口：先做类型过闸校验（autotype 关闭 / deny 命中即阻断）。
     * 仅当类型被显式允许时，才实例化并通过 setter 设值。
     */
    public static void safeDemo(String typeName, String dataSourceName) {
        // [CHECKPOINT id=JSEF-GM-001S cwe=502 level=L3 source=@type sink=deny/autotype-off block expect=SAFE]
        if (!ALLOWLIST.contains(typeName)) { // 安全处理行：autotype 关闭 / deny 命中，阻断实例化
            throw new IllegalArgumentException("type denied (autotype off / deny-list): " + typeName);
        }
        // 即便通过，亦不主动触发 lookup：安全实现中 setter 不再驱动 JNDI sink
        JndiRowSetSafe stub = new JndiRowSetSafe();
        stub.setDataSourceNameSafe(dataSourceName);
    }

    /**
     * 安全占位类：setter 仅本地存储，不触发任何 lookup / 网络回连。
     */
    public static class JndiRowSetSafe {
        private String dataSourceName;
        public void setDataSourceNameSafe(String dataSourceName) {
            this.dataSourceName = dataSourceName; // 安全：仅本地字段，无 sink 调用
        }
    }
}
