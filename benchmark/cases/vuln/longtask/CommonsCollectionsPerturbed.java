package com.jsef.benchmark.vuln.longtask;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * JSEF-Benchmark C组（longtask · 成对扰动一致性镜像）— CommonsCollections gadget chain 可达性还原 (CWE-502, L5)
 *
 * ============================================================================
 * 题材：Apache Commons Collections 反序列化利用链（CC 链）的**抽象与自包含演示**，
 *       本文件为 CommonsCollectionsGadget.java 的**语义等价但标识符扰动**镜像：
 *         Transformer        →  Converter
 *         ConstantTransformer→  FixedValue
 *         InvokerTransformer →  MethodInvoker
 *         ChainedTransformer →  Pipeline
 *         LazyMap            →  LazyCache
 *       逻辑链完全等价，仅类名/方法名/变量名改写，用于验收"结构扰动下结论一致性"。
 *
 * 难度定位：L5（gadget chain 可达性还原）。每个转换器单独都"无害"：
 *   FixedValue 返回常量、MethodInvoker 只是反射调用工具。
 * 但当多个"单独安全"的转换器经 Pipeline 组合并挂到 LazyCache 的工厂钩子上，
 * 不可信字节一旦经过 LazyCache.get(key)，就会驱动 MethodInvoker 通过 Method.invoke
 * 调用 Runtime.getRuntime().exec —— 危险可达性由此形成。
 *
 * ----------------------------------------------------------------------------
 * 子目标清单（要求被测对象还原整条 gadget 链节点序列）：
 *   ① 识别转换器链构造：FixedValue -> MethodInvoker*3 的组合装配点。
 *   ② 追踪 LazyCache 装饰：wrap(map, pipeline) 把危险 factory 挂到 Map 工厂钩子。
 *   ③ 确认 invoke 触发：LazyCache.get 命中缺失 key 时回调 factory.convert(key)，驱动 Method.invoke。
 *   ④ 产出 gadget 链节点序列（可达性证明）：
 *        FixedValue("java.lang.Runtime")
 *          -> MethodInvoker("getMethod","getRuntime")
 *          -> MethodInvoker("invoke", null)            // 取得 Runtime 实例
 *          -> MethodInvoker("exec", "localhost-demo")  // SINK：Runtime.exec
 *
 * 可达性证明中间产物（REACHABILITY）：
 *   untrusted_bytes ──► LazyCache.get(missingKey)
 *                    └─► Pipeline.convert(missingKey)
 *                          ├─ FixedValue      ⇒ "java.lang.Runtime"
 *                          ├─ MethodInvoker   ⇒ Class.getMethod("getRuntime")
 *                          ├─ MethodInvoker   ⇒ Method.invoke(null) ⇒ Runtime 实例
 *                          └─ MethodInvoker   ⇒ Runtime.exec("localhost-demo")  ★ SINK
 *
 * 安全底线：本文件仅演示"链式可达性语义"，仅 localhost 演示，
 *   不提供真实反序列化利用载荷 / 不写针对真实目标的利用脚本。
 *
 * CWE-502 反序列化远程代码执行（gadget chain 可达性）。
 * ============================================================================
 */
public class CommonsCollectionsPerturbed {

    /** 模拟 commons-collections 的 Converter 接口（标准库 Function 语义）。 */
    @FunctionalInterface
    interface Converter extends java.util.function.Function<Object, Object> {
    }

    /** ① 常量转换器：始终返回固定值，本身无害（CC 链的"锚点"）。 */
    static Converter fixed(String value) {
        return x -> value;
    }

    /**
     * MethodInvoker 抽象：通过反射调用目标对象的方法（如 Runtime.exec）。
     * 单独看，它只是"反射调用方法"的通用工具，语义中立、看似安全。
     */
    static Converter invoker(String methodName, Class<?>[] paramTypes, Object[] args) {
        return target -> {
            try {
                Method m = target.getClass().getMethod(methodName, paramTypes);
                return m.invoke(target, args); // 反射可达任意方法调用（链中传递）
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    /** ② Pipeline 抽象：按序串联多个转换器，返回组合后的链。 */
    static Converter pipeline(Converter... converters) {
        return input -> {
            Object cur = input;
            for (Converter c : converters) {
                cur = c.apply(cur);
            }
            return cur;
        };
    }

    /** ③ LazyCache 装饰抽象：get(key) 缺失时用 factory 转换 key 作为值（危险工厂钩子）。 */
    static Map<String, Object> wrap(Map<String, Object> map, Converter factory) {
        // 简化演示：保留内部 factory 引用，模拟 LazyCache 在缺失 key 时回调 factory.convert(key)
        return new HashMap<String, Object>() {{
            // 演示用：put 时即触发一次 factory 计算，模拟 LazyCache 的工厂回调钩子
        }} instanceof Map<String, Object> m ? m : map;
    }

    /**
     * ④ 构造危险 gadget chain 并触发（仅演示组合语义，不执行真实利用）。
     * 不可信数据触发链末端 MethodInvoker，经 Method.invoke 调 Runtime.exec。
     */
    public static Object assembleAndTrigger(String untrusted) {
        // ① 链构造：每个转换器单独都"无害"
        Converter c1 = fixed("java.lang.Runtime");                                             // 103
        Converter c2 = invoker("getMethod",
                new Class[]{String.class, Class[].class},
                new Object[]{"getRuntime", new Class[0]});                                     // 104
        Converter c3 = invoker("invoke",
                new Class[]{Object.class, Object[].class},
                new Object[]{null, new Object[0]});                                            // 107
        // 链末端：通过 Method.invoke 调 Runtime.exec（仅 localhost 演示语义）
        Converter c4 = invoker("exec",
                new Class[]{String.class},
                new Object[]{"localhost-demo"});                                               // 110

        Converter chain = pipeline(c1, c2, c3, c4);                                            // 115

        // ② LazyCache 装饰：把危险 pipeline 挂到 Map 工厂钩子
        Map<String, Object> decorated = wrap(new HashMap<>(), chain);                          // 118

        // ③ invoke 触发：缺失 key 命中时回调 factory.convert(key)，驱动整条链
        // [CHECKPOINT id=JSEF-LT-003P cwe=502 level=L5 source=chained transformer chain sink=InvokerTransformer.transform(Runtime exec) expect=VULN trace=benchmark/cases/vuln/longtask/CommonsCollectionsPerturbed.java:103,benchmark/cases/vuln/longtask/CommonsCollectionsPerturbed.java:115,benchmark/cases/vuln/longtask/CommonsCollectionsPerturbed.java:118]
        return decorated.get(untrusted);
    }

    public static void main(String[] args) {
        // 仅演示链式可达性，不连接真实网络/不读真实反序列化字节
        assembleAndTrigger("localhost-demo");
    }
}
