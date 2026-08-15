package com.jsef.benchmark.vuln.tcm;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * TCM-3 二次解析 / 缓存绕过（Parser Cache Bypass）
 * =================================================
 * 核心范式 P0 的变体：系统在首次解析时执行「安全校验」并拒绝危险类型，
 * 却把攻击者可控的 @type 值缓存进 Map；第二次 reParse 时直接复用缓存的
 * 类型字符串，跳过校验，完成 Class.forName(...).newInstance() 实例化，
 * 隐式构造 / 初始化逻辑抵达危险 sink。
 *
 * 对应 某JSON反序列化库 2.0.x「二次解析 / 反序列化器缓存绕过」：
 *   某些版本在首次解析时已校验 @type 被拒，但缓存层仍记录了该类型名；
 *   后续对同一类型做 re-parse（或反序列化器缓存命中）时不再二次校验，
 *   导致白名单 / denyList 被缓存绕过。
 *
 * 本样本与任何具体 JSON/序列化库无关，仅用 Java 标准库语义自包含复现。
 * 仅 localhost 演示语义，所有危险调用使用 "localhost-demo" 占位字符串。
 */
public class TCM3_ParserCacheBypass {

    // 模拟解析器缓存（真实漏洞里是反序列化器 / 类型缓存）
    private final Map<String, String> typeCache = new HashMap<>();

    // 服务端的「白名单」——只允许无害类型
    private static boolean isAllowed(String type) {
        return "com.jsef.benchmark.vuln.tcm.DemoBean".equals(type);
    }

    /**
     * L3：二次解析缓存绕过
     * 第一次 parse 校验拒绝，但把 @type 写入缓存；
     * 第二次 reParse 直接 Class.forName(cached).newInstance() 跳过校验。
     */
    public void handle(String payload) throws Exception {
        // 第一次解析：抽取 @type，命中白名单校验后拒绝
        // [VULN] 缓存写入：危险类型被拒，但 @type 值仍被缓存
        typeCache.put("@type", extractType(payload)); // 行：缓存写入（绕过起点）

        // 第二次 reParse：直接复用缓存，不再校验
        String cachedType = typeCache.get("@type");
        Class<?> c = Class.forName(cachedType);
        // [CHECKPOINT id=JSEF-TCM-301 cwe=502 level=L3 source=cached @type (bypassed re-parse) sink=Class.forName(cached).newInstance() expect=VULN trace=benchmark/cases/vuln/tcm/TCM3_ParserCacheBypass.java:41,benchmark/cases/vuln/tcm/TCM3_ParserCacheBypass.java:47]
        Object obj = c.newInstance(); // 缓存绕过后的实例化，触发隐式初始化 sink
        System.out.println("re-parsed: " + obj);
    }

    // 简单抽取 payload 中的 @type 值（localhost 演示用，不解析真实 JSON）
    private static String extractType(String payload) {
        // 演示：假设 payload 形如 "@type=evil.Class"
        if (payload != null && payload.contains("@type=")) {
            return payload.substring(payload.indexOf("@type=") + 6).trim();
        }
        return "com.jsef.benchmark.vuln.tcm.DemoBean";
    }

    /**
     * L5：缓存绕过 + Function 抽象链末端反射 exec
     * ================================================
     * 仿仓库 CommonsCollectionsGadget.java:106-121 的 Transformer/invoker 写法，
     * 主题改为「缓存绕过后触发反射 exec」——不依赖任何第三方库。
     * 链：缓存绕过拿到类型 -> 通过 invoker Function 反射调用 Runtime.exec。
     */
    public void handleChain(String payload) throws Exception {
        // 缓存写入（与 L3 同一缺陷起点）
        // [VULN] 缓存写入危险类型，绕过白名单
        typeCache.put("@type", extractType(payload)); // 行：缓存写入（链起点）

        String cachedType = typeCache.get("@type");

        // 仿 Transformer：根据类型名返回一个执行器 Function
        Function<String, Object> invoker = (type) -> {
            try {
                // 反射拿到 Runtime 并 exec（localhost-demo 占位）
                Class<?> rt = Class.forName("java.lang.Runtime");
                java.lang.reflect.Method getRuntime = rt.getMethod("getRuntime");
                Object runtime = getRuntime.invoke(null);
                // [VULN] 隐式方法链路末端：反射 invoke Runtime.exec
                java.lang.reflect.Method exec = rt.getMethod("exec", String.class);
                // [CHECKPOINT id=JSEF-TCM-302 cwe=502 level=L5 source=cache-bypassed type sink=invoker.transform->Runtime.exec expect=VULN trace=benchmark/cases/vuln/tcm/TCM3_ParserCacheBypass.java:70,benchmark/cases/vuln/tcm/TCM3_ParserCacheBypass.java:83,benchmark/cases/vuln/tcm/TCM3_ParserCacheBypass.java:84]
                return exec.invoke(runtime, "localhost-demo"); // 仅占位，不连真实远端
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };

        // 链末端触发：缓存绕过后的类型驱动反射 exec
        invoker.apply(cachedType);
    }

    // 无害演示 Bean（仅用于白名单命中分支）
    public static class DemoBean {
        @Override
        public String toString() {
            return "DemoBean(benign)";
        }
    }
}
