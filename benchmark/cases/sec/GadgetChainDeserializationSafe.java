package com.jsef.benchmark.sec;

import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark L5 — gadget chain 安全对照（SAFE 混淆样本）
 *
 * 安全做法（针对 CWE-502 反序列化链）：
 *  1) 不允许危险类型进入转换器链；使用仅含"无害常量/白名单方法"的 SafeTransformer，
 *     不提供任意 Method.invoke 反射能力。
 *  2) 或使用"不可变常量链"——所有中间值都是编译期常量，不可由不可信输入驱动。
 *
 * 这样即便组合多个转换器，也无法形成 Runtime.exec 可达性，不应报（计入 TN / FP）。
 *
 * CWE-502 反序列化远程代码执行。
 */
public class GadgetChainDeserializationSafe {

    @FunctionalInterface
    interface SafeTransformer {
        Object apply(Object in);
    }

    private static final List<String> ALLOWED_METHODS = Arrays.asList("toString", "toLowerCase");

    /**
     * SafeTransformer：仅允许白名单内的无害方法，拒绝任何反射式危险调用。
     */
    static SafeTransformer safeInvoker(String methodName) {
        if (!ALLOWED_METHODS.contains(methodName)) {
            throw new IllegalArgumentException("method not allowed in safe chain: " + methodName);
        }
        return in -> {
            try {
                return in.getClass().getMethod(methodName).invoke(in);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    /**
     * 不可变常量链：所有步骤都是编译期常量/白名单方法，不可信输入不参与链路。
     */
    public static Object buildSafeChain(String untrusted) {
        SafeTransformer s1 = in -> "localhost-demo";          // 常量，丢弃不可信输入
        SafeTransformer s2 = safeInvoker("toLowerCase");      // 仅白名单无害方法
        SafeTransformer s3 = in -> "noop:" + in;              // 常量拼接，无反射 exec

        // [CHECKPOINT id=JSEF-GADGET-001S cwe=502 level=L5 source=untrusted bytes sink=Method.invoke(exec) expect=SAFE]
        Object cur = untrusted; // 不可信输入被 s1 立即替换为常量，未进入危险 reflection 路径
        cur = s1.apply(cur);
        cur = s2.apply(cur);
        cur = s3.apply(cur);
        return cur;
    }

    public static void main(String[] args) {
        buildSafeChain("attacker-controlled");
    }
}
