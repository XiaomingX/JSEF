package com.jsef.benchmark.vuln;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * JSEF-Benchmark L5 — gadget chain / 状态机（反序列化可达性）
 *
 * 这是 Apache Commons Collections 反序列化利用链（CVE-2015-7501 / CVE-2015-6420，
 * 即 CC 链：InvokerTransformer + ChainedTransformer + LazyMap）的**抽象与自包含演示**。
 * 为不依赖第三方库，这里用标准库 Map / Function 模拟同名组件的语义：
 *   - Transformer  ~  Function<Object,Object>
 *   - ChainedTransformer ~ 组合多个 Transformer 顺序执行
 *   - InvokerTransformer  ~ 通过反射 Method.invoke 调用任意方法
 *   - LazyMap 装饰  ~ 在 get(key) 缺失时回调 chainedTransformer.transform(key)
 *
 * 关键点（L5 难度，CAP-10）：
 *   每个转换器单独看都"无害"——ConstantTransformer 返回常量、InvokerTransformer 只是反射调用。
 *   但当多个"单独安全"的转换器经 ChainedTransformer 组合、并挂到 LazyMap 的工厂钩子上时，
 *   不可信字节一旦触发 LazyMap.get(key)，就会驱动 InvokerTransformer 通过 Method.invoke
 *   调用 Runtime.getRuntime().exec —— 危险可达性形成。
 *   纯语法 SAST 难以识别此类"跨类组合才危险"的链路，需跨类可达性 / 数据流分析。
 *
 * 安全底线：本文件仅演示链式可达性语义，仅 localhost 演示，不提供真实反序列化利用载荷/脚本。
 *
 * CWE-502 反序列化远程代码执行。
 */
public class GadgetChainDeserialization {

    /** 模拟 commons-collections 的 Transformer 接口（标准库 Function 语义）。 */
    @FunctionalInterface
    interface Transformer extends Function<Object, Object> {
    }

    /** 常量转换器：始终返回固定值，本身无害。 */
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
                return m.invoke(target, args); // 反射可达任意方法调用
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    /** ChainedTransformer 抽象：按序串联多个转换器。 */
    static Transformer chained(Transformer... transformers) {
        return input -> {
            Object cur = input;
            for (Transformer t : transformers) {
                cur = t.apply(cur);
            }
            return cur;
        };
    }

    /**
     * LazyMap 装饰抽象：get(key) 缺失时，用 factory 转换 key 作为值。
     * 危险在于：factory 是被污染的 ChainedTransformer，而非无害函数。
     */
    static Map<String, Object> lazyMap(Map<String, Object> map, Transformer factory) {
        return new HashMap<String, Object>() {{
            // 简化演示：put 时即触发一次 factory 计算，模拟 LazyMap 的工厂回调钩子
        }} instanceof Map<String, Object> m ? m : map;
    }

    /**
     * 构造危险 gadget chain（仅演示组合语义，不执行真实利用）。
     * 不可信数据触发链末端 InvokerTransformer，经 Method.invoke 调 Runtime.exec。
     */
    public static Object buildGadgetAndTrigger(String untrusted) {
        // 单独的转换器都"无害"：常量、反射调用工具
        Transformer t1 = constant("java.lang.Runtime");
        Transformer t2 = invoker("getMethod",
                new Class[]{String.class, Class[].class},
                new Object[]{"getRuntime", new Class[0]});
        Transformer t3 = invoker("invoke",
                new Class[]{Object.class, Object[].class},
                new Object[]{null, new Object[0]});
        // 危险 sink：通过 Method.invoke 调 Runtime.exec（仅 localhost 演示语义）
        Transformer t4 = invoker("exec",
                new Class[]{String.class},
                new Object[]{"echo localhost-demo"});

        Transformer chain = chained(t1, t2, t3, t4);

        // 不可信输入触发链：组合后形成 Runtime.exec 可达性
        // [CHECKPOINT id=JSEF-GADGET-001 cwe=502 level=L5 source=untrusted bytes sink=Method.invoke(exec) expect=VULN trace=benchmark/cases/vuln/GadgetChainDeserialization.java:96,benchmark/cases/vuln/GadgetChainDeserialization.java:100]
        return chain.apply(untrusted);
    }

    public static void main(String[] args) {
        // 仅演示链式可达性，不连接真实网络/不读真实反序列化字节
        buildGadgetAndTrigger("localhost-demo");
    }
}
