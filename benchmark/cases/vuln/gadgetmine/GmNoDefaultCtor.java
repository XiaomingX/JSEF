package com.jsef.benchmark.vuln.gadgetmine;

/**
 * JSEF-Benchmark gadgetmine 族 — 验收维度 §一 (7)：可实例化
 * ============================================================
 * 验收目标：被测工具（LLM / SAST）能否从第一性原理判定
 *   fastjson AutoType RCE gadget 的"可实例化"充要条件。
 *
 * 本题结论（应为 SAFE）：
 *   目标类 `NoDefaultCtorGadgetStub` 仅有带参私有构造器，
 *   既无 public 无参构造，也无 @JSONCreator 工厂方法。
 *   fastjson 在 AutoType 下对 `@type` 指定的类需要可实例化
 *   （默认通过无参构造或 @JSONCreator 实例化）；缺少可用入口时
 *   无法构造对象，故该类型不构成可达 gadget，应判 SAFE。
 *
 * 安全底线声明：仅 localhost 演示语义。本文件不 import 任何真实
 *   fastjson，不提供真实攻击利用脚本；占位类仅用于表达"不可实例化"
 *   的 gadget 判定语义。
 */
public class GmNoDefaultCtor {

    /**
     * 教学占位 gadget 类：无可用构造入口。
     * 不 import com.alibaba.fastjson —— 本项目不引入真实 fastjson。
     */
    // 占位类：仅带参私有构造器，无 public 无参构造、无 @JSONCreator。
    public static class NoDefaultCtorGadgetStub {
        // 仅私有带参构造，fastjson 无法实例化此类
        private NoDefaultCtorGadgetStub(String secret, int nonce) {
            // 私有带参构造：AutoType 无入口可实例化
        }
    }

    /**
     * 模拟 AutoType 按 @type 解析目标类并实例化的过程。
     * 此处刻意表达"目标类无默认构造 -> 不可实例化 -> 不构成 gadget"。
     */
    public static Object resolveViaType(String typeName) {
        // @type 指定 NoDefaultCtorGadgetStub
        // [CHECKPOINT id=JSEF-GM-005 cwe=502 level=L2 source=@type sink=class instantiation (no default ctor) expect=SAFE]
        Object instance = instantiateByType(typeName);  // SAFE：目标类无默认构造，无法实例化
        return instance;
    }

    /**
     * 模拟 fastjson 按类型名实例化：真实 fastjson 会尝试无参构造 /
     * @JSONCreator；本占位仅打印语义。
     */
    private static Object instantiateByType(String typeName) {
        System.out.println("[demo-only] attempt instantiate (no default ctor): " + typeName);
        return null;  // 占位：无默认构造 -> 实例化失败
    }
}
