/*
 * JSEF Benchmark 样本 — 反射注入（安全对照）：allowlist 类名映射（B1 组，CWE-470，L4）
 *
 * ① 子目标清单：
 *    - 演示如何修正反射注入：不可信类名不得直接进入 Class.forName。
 *    - 用受控别名映射表，仅允许加载预注册的类。
 * ② 可达性说明：
 *    - className 经 ALLOWED 映射为固定全限定名；不在映射内的输入被拒绝。
 *    - Class.forName 只接收受控常量字符串，invoke 不再可达任意类。
 * ③ 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 * ④ 修复要点：allowlist 别名映射 + 拒绝未知别名，反射目标完全受控。
 */
package com.jsef.benchmark.sec.reflectioninjection;

import java.util.Map;

public class ReflectionInjection_Safe {

    // 受控别名 → 固定全限定类名（allowlist）
    private static final Map<String, String> ALLOWED = Map.of(
            "greeter", "com.jsef.benchmark.sec.reflectioninjection.Greeter",
            "formatter", "com.jsef.benchmark.sec.reflectioninjection.Formatter"
    );

    public Object invokeTrusted(String alias, String methodName, Object... args) throws Exception {
        // 修复：别名映射到固定类名，未知别名直接拒绝
        String className = ALLOWED.get(alias);
        if (className == null) {
            throw new IllegalArgumentException("unknown alias");
        }
        // [CHECKPOINT id=JSEF-REFLECT-001S cwe=470 level=L4 source=HttpServletRequest parameter sink=Method.invoke expect=SAFE trace=benchmark/cases/sec/reflection-injection/ReflectionInjection_Safe.java:20,benchmark/cases/sec/reflection-injection/ReflectionInjection_Safe.java:32,benchmark/cases/sec/reflection-injection/ReflectionInjection_Safe.java:33]
        Class<?> clazz = Class.forName(className);
        return clazz.getMethod(methodName).invoke(null, args);
    }
}
