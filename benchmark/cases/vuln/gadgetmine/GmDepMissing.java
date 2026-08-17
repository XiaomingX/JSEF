package com.jsef.benchmark.vuln.gadgetmine;

/**
 * JSEF-Benchmark gadgetmine 族 — GmDepMissing (JSEF-GM-004, CWE-502, L2)
 * ============================================================================
 * 验收维度：§一 (11) 依赖缺失（0 误报关键）。
 *
 * 判定语义：fastjson gadget 的可达性依赖完整的调用链类都存在于目标 classpath。若 gadget
 * 类及其调用链上的依赖（如 c3p0、ibatis 等）在目标运行环境（如 fastjson 1.2.84）中未被
 * 引入，则该链"不可达"——工具若报告此链路，即为误报（false positive）。被测工具必须从
 * 第一性原理判定：依赖缺失 = 链不可达 = SAFE（不应报）。
 *
 * 教学占位说明：
 *   - 不 import com.alibaba.fastjson，不引入任何第三方 gadget 依赖。
 *   - ThirdPartyGadgetStub 注释声明：该类在 1.2.84 目标环境 classpath 中不存在
 *     （如 c3p0 / ibatis 未引入）。因此即便 @type 指定它，也无法在目标环境加载，
 *     不构成可达 gadget。
 *   - level=L2（多跳无断点判定），无 trace（单点直连语义）。
 *
 * 安全底线声明：仅 localhost 演示语义，不提供真实利用脚本，不构造针对真实目标的链。
 */
public class GmDepMissing {

    /**
     * 教学占位 gadget 类：声明在目标 classpath 中不存在。
     * 注意：真实 fastjson 1.2.84 目标环境未引入 c3p0 / ibatis 等依赖，
     * 故此类无法被 ClassLoader 加载，gadget 链断裂、不可达。
     */
    public static class ThirdPartyGadgetStub {
        private Object dataSource;

        /**
         * 危险 setter（仅语义占位）：真实环境中应由 c3p0/ibatis 提供，
         * 但目标 classpath 缺失该依赖，本类根本不会被实例化。
         */
        public void setDataSource(Object ds) {
            System.out.println("[demo-only] third-party gadget setter (unreachable in target): " + ds);
            this.dataSource = ds;
        }
    }

    /**
     * 模拟 AutoType 解析：按 @type 实例化。若目标 classpath 无该类，则 ClassNotFoundException，
     * 链路中断 → 不可达 gadget → 应判 SAFE（工具不应误报该链存在）。
     */
    public static Object parseWithAutoType(String typeName) {
        // 该类在 1.2.84 目标环境 classpath 中不存在（c3p0/ibatis 未引入）
        // [CHECKPOINT id=JSEF-GM-004 cwe=502 level=L2 source=@type sink=classpath-missing (依赖缺失 不可达) expect=SAFE]
        if (!isOnTargetClasspath(typeName)) {  // 目标 classpath 缺失依赖 → 链不可达
            throw new IllegalStateException("class not on target classpath: " + typeName);
        }
        ThirdPartyGadgetStub stub = new ThirdPartyGadgetStub();
        stub.setDataSource("attacker-controlled");
        return stub;
    }

    /**
     * 模拟"目标运行环境 classpath 是否含该类"的判定（localhost 演示语义）。
     * 真实场景由目标环境实际依赖决定；此处占位声明 ThirdPartyGadgetStub 不在范围内。
     */
    private static boolean isOnTargetClasspath(String typeName) {
        // 演示：c3p0 / ibatis 等依赖在 1.2.84 目标环境未引入，故返回 false
        return typeName != null
                && !typeName.startsWith("com.mchange.v2.c3p0.")
                && !typeName.startsWith("com.ibatis.");
    }
}
