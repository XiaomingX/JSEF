package com.jsef.benchmark.vuln.gadgetmine;

/**
 * JSEF-Benchmark gadgetmine 族 — GmDenyListBlocked (JSEF-GM-003, CWE-502, L3)
 * ============================================================================
 * 验收维度：§一 (4) 黑名单拦截（fastjson 内置 denyHashCodes 生效）。
 *
 * 判定语义：即便 fastjson 的 autoTypeSupport 开启，内置 deny 名单（denyHashCodes）
 * 仍然生效。commons-collections 的
 * `org.apache.commons.collections.functors.InvokerTransformer` 等危险类名命中 deny
 * 前缀/哈希，AutoType 直连实例化在到达危险 setter 之前即被拦截。因此该类虽"含危险
 * setter"，但在 deny 名单保护下不构成可达（reachable）RCE gadget。
 *
 * 教学占位说明：
 *   - 本文件不 import com.alibaba.fastjson，全部使用占位类 + 模拟 sink 表达语义。
 *   - DenyListGadgetStub 名义上具备危险 setter（setValue 触发危险调用），但类名落在
 *     fastjson deny 前缀拦截范围内，AutoType 直连被拦，无法到达 sink。
 *   - 被测工具应从第一性原理判定：命中 deny 名单 = 直连被拦 = 不构成可达 gadget = SAFE。
 *
 * 安全底线声明：仅 localhost 演示语义。不引入真实 fastjson 依赖，不提供任何真实攻击
 * 利用脚本，不构造针对真实目标的利用链。占位类的危险调用仅为模拟打印，无真实危害。
 */
public class GmDenyListBlocked {

    /**
     * 教学占位 gadget 类：名义上含危险 setter，但类名命中 fastjson 内置 deny 名单前缀
     * （如 org.apache.commons.collections.functors.*）。AutoType 开启时直连实例化会被
     * denyHashCodes 在反序列化入口处拦截，危险 setter 永不执行。
     */
    public static class DenyListGadgetStub {
        private Object payload;

        /**
         * 危险 setter（仅语义占位）：真实 fastjson gadget 链中 InvokerTransformer 的
         * setValue 会触发方法反射调用。此处仅模拟，无真实危害。
         */
        public void setValue(Object v) {
            // 模拟危险调用（demo-only，不引真实依赖）
            System.out.println("[demo-only] deny-listed gadget setter invoked: " + v);
            this.payload = v;
        }
    }

    /**
     * 模拟 AutoType 解析入口：按 @type 指定的类名实例化。
     * 关键点：在真正 newInstance 之前，fastjson 会查 denyHashCodes；命中即抛异常拦截。
     */
    public static Object parseWithAutoType(String typeName) {
        // 模拟 fastjson denyHashCodes 检查：若 typeName 命中 deny 前缀则直接拦截
        // 例如 "org.apache.commons.collections.functors.InvokerTransformer" 命中 deny 名单
        if (isDenyListed(typeName)) {
            // [CHECKPOINT id=JSEF-GM-003 cwe=502 level=L3 source=@type sink=denyHashCodes block (直连被拦) expect=SAFE]
            throw new IllegalArgumentException("fastjson deny list blocked: " + typeName);  // deny 拦截，直连不可达
        }
        // 下列危险 setter 在 deny 拦截下永不执行，故不构成可达 gadget
        DenyListGadgetStub stub = new DenyListGadgetStub();
        stub.setValue("attacker-controlled");
        return stub;
    }

    /**
     * 模拟 fastjson 内置 denyHashCodes 前缀匹配（仅 localhost 演示语义）。
     */
    private static boolean isDenyListed(String typeName) {
        // 真实 fastjson 用哈希比对，这里以前缀占位表达"命中内置 deny 名单"语义
        return typeName != null
                && (typeName.startsWith("org.apache.commons.collections.functors.")
                    || typeName.startsWith("com.sun.")
                    || typeName.startsWith("org.apache.xalan."));
    }
}
