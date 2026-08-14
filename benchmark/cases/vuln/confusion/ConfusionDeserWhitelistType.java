package com.jsef.benchmark.vuln;

import java.lang.reflect.Method;

/**
 * JSEF-Benchmark Phase5-B — 命名混淆（vendor 风格，单文件双 checkpoint，CWE-502 不安全反序列化，难度 L3）
 *
 * 混淆点（为什么容易被误判）：
 * 类名与方法名都带有 "Safe"/"Allowlist" 字眼，强烈暗示"已授权/已受控"。
 * 弱被测对象在命名层面即被安抚，直接判定为安全（FP 风险在对照段，
 * 但本段是 VULN，命名诱导导致漏报 FN）。实际上 it 仍通过反射调用了危险方法
 * （如 runtime.exec / 任意方法 invoke），白名单只是"验证类名在名单里"，
 * 并未限制该类能做什么——名单内的类本身就能执行危险操作。
 *
 * 仿 OwaspStyle 单文件双 checkpoint 写法：同文件内 VULN 段与 SAFE 段紧邻。
 *
 * 安全底线：Payload 仅 localhost 演示语义；反射调用仅表达 sink 语义，不提供真实 gadget。
 */
public class ConfusionDeserWhitelistType {

    // 看似"白名单"，但名单内的类型本身即可执行危险操作
    static final java.util.Set<String> TRUSTED = java.util.Set.of(
            "com.demo.LegacyHandler", "com.demo.LegacyService");

    /**
     * VULN 段：类名在白名单即放行，再用反射调用其方法（方法名亦来自输入）。
     */
    static Object unsafeDeser(String className, String methodName) throws Exception {
        if (!TRUSTED.contains(className)) {
            throw new IllegalArgumentException("type not allowed"); // 仅校验类名
        }
        Class<?> clazz = Class.forName(className); // 受名单约束，但类本身危险
        Object instance = clazz.getDeclaredConstructor().newInstance();
        Method m = clazz.getMethod(methodName); // 方法名来自输入
        // [CHECKPOINT id=JSEF-NC-001 cwe=502 level=L3 source=methodName (user-controlled) sink=Method.invoke(exec) expect=VULN]
        return m.invoke(instance); // 反射调用危险方法：仍不安全反序列化利用链
    }

    /**
     * SAFE 段：真正 allowlist —— 既限制类名，又限制可调用的具体方法签名，
     * 且不使用反射执行任意方法。
     */
    static String safeDeser(String className) {
        // 真正的白名单：只允许一个无副作用的只读方法
        if (!"com.demo.LegacyService".equals(className)) {
            throw new IllegalArgumentException("type not allowed");
        }
        // [CHECKPOINT id=JSEF-NC-001S cwe=502 level=L3 source=className (allowlist-checked) sink=no reflection / fixed method expect=SAFE]
        return "ok"; // 不反射、不执行任意方法，安全
    }
}
