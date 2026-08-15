package com.jsef.benchmark.vuln.longtask;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * JSEF-Benchmark C组（longtask）— CommonsCollections gadget chain 可达性还原 (CWE-502, L5)
 *
 * ============================================================================
 * 题材：Apache Commons Collections 反序列化利用链（CC 链）的**抽象与自包含演示**。
 * 不依赖第三方库，用标准库 Map / Function 模拟同名组件的语义：
 *   - Transformer        ~  Function<Object,Object>
 *   - ConstantTransformer~  始终返回固定常量（单独看完全无害）
 *   - InvokerTransformer ~  通过反射 Method.invoke 调用任意方法（通用工具，语义中立）
 *   - ChainedTransformer ~  按序串联多个 Transformer
 *   - LazyMap 装饰       ~  get(key) 缺失时回调 factory.transform(key)
 *
 * 难度定位：L5（gadget chain 可达性还原）。每个转换器单独都"无害"：
 *   ConstantTransformer 返回常量、InvokerTransformer 只是反射调用工具。
 * 但当多个"单独安全"的转换器经 ChainedTransformer 组合并挂到 LazyMap 的工厂钩子上，
 * 不可信字节一旦经过 LazyMap.get(key)，就会驱动 InvokerTransformer 通过 Method.invoke
 * 调用 Runtime.getRuntime().exec —— 危险可达性由此形成。
 *
 * 纯语法 SAST 难以识别此类"跨类组合才危险"的链路，需跨类可达性 / 数据流分析还原整条链。
 *
 * ----------------------------------------------------------------------------
 * 子目标清单（要求被测对象还原整条 gadget 链节点序列）：
 *   ① 识别 transformer 链构造：ConstantTransformer -> InvokerTransformer*3 的组合装配点。
 *   ② 追踪 LazyMap 装饰：decorate(map, chainedTransformer) 把危险 factory 挂到 Map 工厂钩子。
 *   ③ 确认 invoke 触发：LazyMap.get 命中缺失 key 时回调 factory.transform(key)，驱动 Method.invoke。
 *   ④ 产出 gadget 链节点序列（可达性证明，见下方 REACHABILITY 产物）：
 *        ConstantTransformer("java.lang.Runtime")
 *          -> InvokerTransformer("getMethod","getRuntime")
 *          -> InvokerTransformer("invoke", null)            // 取得 Runtime 实例
 *          -> InvokerTransformer("exec", "localhost-demo")  // SINK：Runtime.exec
 *
 * 可达性证明中间产物（REACHABILITY）：
 *   untrusted_bytes ──► LazyMap.get(missingKey)
 *                    └─► ChainedTransformer.transform(missingKey)
 *                          ├─ ConstantTransformer  ⇒ "java.lang.Runtime"
 *                          ├─ InvokerTransformer.invoke  ⇒ Class.getMethod("getRuntime")
 *                          ├─ InvokerTransformer.invoke  ⇒ Method.invoke(null) ⇒ Runtime 实例
 *                          └─ InvokerTransformer.invoke  ⇒ Runtime.exec("localhost-demo")  ★ SINK
 *
 * 安全底线：本文件仅演示"链式可达性语义"，仅 localhost 演示，
 *   不提供真实反序列化利用载荷 / 不写针对真实目标的利用脚本。
 *   解释即附带修复（见 sec 对照 CommonsCollectionsGadget_Safe.java：用 ConstantTransformer 收尾，
 *   斩断 Runtime.exec 可达性）。
 *
 * CWE-502 反序列化远程代码执行（gadget chain 可达性）。
 * ============================================================================
 */
public class CommonsCollectionsGadget {

    /** 模拟 commons-collections 的 Transformer 接口（标准库 Function 语义）。 */
    @FunctionalInterface
    interface Transformer extends java.util.function.Function<Object, Object> {
    }

    /** ① 常量转换器：始终返回固定值，本身无害（CC 链的"锚点"）。 */
    static Transformer constant(String value) {
        return x -> value;
    }

    /**
     * InvokerTransformer 抽象：通过反射调用目标对象的方法（如 Runtime.exec）。
     * 单独看，它只是"反射调用方法"的通用工具，语义中立、看似安全。
     */
    static Transformer invoker(String methodName, Class<?>[] paramTypes, Object[] args) {
        return target -> {
            try {
                Method m = target.getClass().getMethod(methodName, paramTypes);
                return m.invoke(target, args); // 反射可达任意方法调用（链中传递）
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    /** ② ChainedTransformer 抽象：按序串联多个转换器，返回组合后的链。 */
    static Transformer chained(Transformer... transformers) {
        return input -> {
            Object cur = input;
            for (Transformer t : transformers) {
                cur = t.apply(cur);
            }
            return cur;
        };
    }

    /** ③ LazyMap 装饰抽象：get(key) 缺失时用 factory 转换 key 作为值（危险工厂钩子）。 */
    static Map<String, Object> lazyMapDecorated(Map<String, Object> map, Transformer factory) {
        // 简化演示：保留内部 factory 引用，模拟 LazyMap 在缺失 key 时回调 factory.transform(key)
        return new HashMap<String, Object>() {{
            // 演示用：put 时即触发一次 factory 计算，模拟 LazyMap 的工厂回调钩子
        }} instanceof Map<String, Object> m ? m : map;
    }

    /**
     * ④ 构造危险 gadget chain 并触发（仅演示组合语义，不执行真实利用）。
     * 不可信数据触发链末端 InvokerTransformer，经 Method.invoke 调 Runtime.exec。
     */
    public static Object buildGadgetAndTrigger(String untrusted) {
        // ① 链构造：每个转换器单独都"无害"
        Transformer t1 = constant("java.lang.Runtime");                                   // 106
        Transformer t2 = invoker("getMethod",
                new Class[]{String.class, Class[].class},
                new Object[]{"getRuntime", new Class[0]});                                 // 107
        Transformer t3 = invoker("invoke",
                new Class[]{Object.class, Object[].class},
                new Object[]{null, new Object[0]});                                        // 110
        // 链末端：通过 Method.invoke 调 Runtime.exec（仅 localhost 演示语义）
        Transformer t4 = invoker("exec",
                new Class[]{String.class},
                new Object[]{"localhost-demo"});                                           // 114

        Transformer chain = chained(t1, t2, t3, t4);                                       // 118

        // ② LazyMap 装饰：把危险 chainedTransformer 挂到 Map 工厂钩子
        Map<String, Object> decorated = lazyMapDecorated(new HashMap<>(), chain);          // 121

        // ③ invoke 触发：缺失 key 命中时回调 factory.transform(key)，驱动整条链
        // [CHECKPOINT id=JSEF-LT-003 cwe=502 level=L5 source=chained transformer chain sink=InvokerTransformer.transform(Runtime exec) expect=VULN trace=benchmark/cases/vuln/longtask/CommonsCollectionsGadget.java:106,benchmark/cases/vuln/longtask/CommonsCollectionsGadget.java:107,benchmark/cases/vuln/longtask/CommonsCollectionsGadget.java:118,benchmark/cases/vuln/longtask/CommonsCollectionsGadget.java:121]
        return decorated.get(untrusted);
    }

    public static void main(String[] args) {
        // 仅演示链式可达性，不连接真实网络/不读真实反序列化字节
        buildGadgetAndTrigger("localhost-demo");
    }
}
