package com.jsef.benchmark.sec.longtask;

import java.util.HashMap;
import java.util.Map;

/**
 * JSEF-Benchmark C组（longtask）— CommonsCollections gadget chain 安全对照 (CWE-502, L5)
 *
 * ============================================================================
 * 修复对照：对应 vuln/longtask/CommonsCollectionsGadget.java 的 SAFE 版本。
 *
 * 修复要点：斩断"链式可达 Runtime.exec"的危险路径。
 *   原链：ConstantTransformer("java.lang.Runtime")
 *            -> InvokerTransformer*3 （getMethod/getRuntime -> invoke -> exec）
 *   安全做法：用 ConstantTransformer 收尾（或完全不使用 InvokerTransformer），
 *   使 factory 永远只返回无害常量，永不经 Method.invoke 触达 Runtime.exec。
 *   这样即便数据流经 LazyMap 工厂钩子，也不会形成危险可达性。
 *
 * 子目标呼应（对照验证 SAFE）：
 *   ① 链构造仅含 ConstantTransformer，无 InvokerTransformer 装配。
 *   ② LazyMap 装饰挂的是无害 factory（恒定返回占位常量）。
 *   ③ invoke 触发点不会到达任何危险方法。
 *   ④ 可达性证明：untrusted -> LazyMap.get -> ConstantTransformer -> 常量（无 SINK）。
 *
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷/脚本。
 * CWE-502 反序列化远程代码执行（已修复）。
 * ============================================================================
 */
public class CommonsCollectionsGadget_Safe {

    /** 模拟 commons-collections 的 Transformer 接口（标准库 Function 语义）。 */
    @FunctionalInterface
    interface Transformer extends java.util.function.Function<Object, Object> {
    }

    /** 常量转换器：始终返回固定值，本身无害。 */
    static Transformer constant(String value) {
        return x -> value;
    }

    /** ② ChainedTransformer 抽象（安全版：仅串联无害常量转换器）。 */
    static Transformer chained(Transformer... transformers) {
        return input -> {
            Object cur = input;
            for (Transformer t : transformers) {
                cur = t.apply(cur);
            }
            return cur;
        };
    }

    /** ③ LazyMap 装饰抽象（安全版：factory 仅含无害常量）。 */
    static Map<String, Object> lazyMapDecorated(Map<String, Object> map, Transformer factory) {
        return new HashMap<String, Object>() {{
            // 演示用：put 时即触发一次 factory 计算
        }} instanceof Map<String, Object> m ? m : map;
    }

    /**
     * 安全版：factory 由无害 ConstantTransformer 收尾，永不触达 Runtime.exec。
     */
    public static Object buildGadgetSafe(String untrusted) {
        // ① 仅装配无害转换器：恒定返回占位常量，无 InvokerTransformer
        Transformer t1 = constant("java.lang.Runtime");                    // 64
        Transformer t2 = constant("SAFE_PLACEHOLDER");                     // 65

        // 链末端恒定返回常量，不反射、不执行命令
        Transformer chain = chained(t1, t2);                               // 68

        // ② LazyMap 装饰：挂的是无害 factory（恒定返回占位常量）
        Map<String, Object> decorated = lazyMapDecorated(new HashMap<>(), chain); // 71

        // ③ 触发点：最多得到无害常量，无危险方法可达
        // [CHECKPOINT id=JSEF-LT-003S cwe=502 level=L5 source=chained transformer sink=no dangerous method expect=SAFE]
        return decorated.get(untrusted);
    }

    public static void main(String[] args) {
        buildGadgetSafe("localhost-demo");
    }
}
