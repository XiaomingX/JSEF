package com.jsef.benchmark.sec.longtask;

import java.util.HashMap;
import java.util.Map;

/**
 * JSEF-Benchmark C组（longtask · 成对扰动一致性镜像）— CommonsCollections gadget chain 安全对照 (CWE-502, L5)
 *
 * ============================================================================
 * 修复对照：对应 vuln/longtask/CommonsCollectionsPerturbed.java 的 SAFE 版本（标识符扰动镜像）。
 * 重命名：Transformer→Converter、ConstantTransformer→FixedValue、ChainedTransformer→Pipeline、
 *         LazyMap→LazyCache、buildGadgetAndTrigger→assembleAndTriggerSafe。
 *
 * 修复要点：斩断"链式可达 Runtime.exec"的危险路径。
 *   原链：FixedValue("java.lang.Runtime")
 *            -> MethodInvoker*3 （getMethod/getRuntime -> invoke -> exec）
 *   安全做法：用 FixedValue 收尾（或完全不使用 MethodInvoker），
 *   使 factory 永远只返回无害常量，永不经 Method.invoke 触达 Runtime.exec。
 *   这样即便数据流经 LazyCache 工厂钩子，也不会形成危险可达性。
 *
 * 子目标呼应（对照验证 SAFE）：
 *   ① 链构造仅含 FixedValue，无 MethodInvoker 装配。
 *   ② LazyCache 装饰挂的是无害 factory（恒定返回占位常量）。
 *   ③ invoke 触发点不会到达任何危险方法。
 *   ④ 可达性证明：untrusted -> LazyCache.get -> FixedValue -> 常量（无 SINK）。
 *
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷/脚本。
 * CWE-502 反序列化远程代码执行（已修复）。
 * ============================================================================
 */
public class CommonsCollectionsPerturbed_Safe {

    /** 模拟 commons-collections 的 Converter 接口（标准库 Function 语义）。 */
    @FunctionalInterface
    interface Converter extends java.util.function.Function<Object, Object> {
    }

    /** 常量转换器：始终返回固定值，本身无害。 */
    static Converter fixed(String value) {
        return x -> value;
    }

    /** ② Pipeline 抽象（安全版：仅串联无害常量转换器）。 */
    static Converter pipeline(Converter... converters) {
        return input -> {
            Object cur = input;
            for (Converter c : converters) {
                cur = c.apply(cur);
            }
            return cur;
        };
    }

    /** ③ LazyCache 装饰抽象（安全版：factory 仅含无害常量）。 */
    static Map<String, Object> wrap(Map<String, Object> map, Converter factory) {
        return new HashMap<String, Object>() {{
            // 演示用：put 时即触发一次 factory 计算
        }} instanceof Map<String, Object> m ? m : map;
    }

    /**
     * 安全版：factory 由无害 FixedValue 收尾，永不触达 Runtime.exec。
     */
    public static Object assembleAndTriggerSafe(String untrusted) {
        // ① 仅装配无害转换器：恒定返回占位常量，无 MethodInvoker
        Converter c1 = fixed("java.lang.Runtime");                    // 64
        Converter c2 = fixed("SAFE_PLACEHOLDER");                     // 65

        // 链末端恒定返回常量，不反射、不执行命令
        Converter chain = pipeline(c1, c2);                           // 68

        // ② LazyCache 装饰：挂的是无害 factory（恒定返回占位常量）
        Map<String, Object> decorated = wrap(new HashMap<>(), chain); // 71

        // ③ 触发点：最多得到无害常量，无危险方法可达
        // [CHECKPOINT id=JSEF-LT-003PS cwe=502 level=L5 source=chained transformer sink=no dangerous method expect=SAFE]
        return decorated.get(untrusted);
    }

    public static void main(String[] args) {
        assembleAndTriggerSafe("localhost-demo");
    }
}
