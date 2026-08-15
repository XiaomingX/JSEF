/*
 * JSEF Benchmark 样本 — 反射注入：不可信类名 Class.forName 后 getMethod().invoke()（B1 组，CWE-470，L4）
 *
 * ① 子目标清单：
 *    - 演示"反射注入"：攻击者控制的类名/方法名经反射 API 加载并调用，等于任意代码执行。
 *    - 展示跨方法数据流：source（请求参数）→ forName（加载）→ getMethod/invoke（调用）。
 *    - 让静态分析跨方法/跨节点识别污点到达 invoke sink。
 * ② 可达性说明：
 *    - source：Controller 形参 className / methodName（来自 HTTP 请求）。
 *    - forName：Class.forName(className) 加载攻击者指定类（跨信任边界）。
 *    - invoke：clazz.getMethod(methodName).invoke(...) 在加载类上执行任意方法。
 *    - data flow：className → forName → getMethod → invoke，全链未校验。
 * ③ 安全底线：仅 localhost 演示语义，不写真实利用脚本，不提供可触发的 gadget 链。
 * ④ 修复要点：见 sec 文件 ReflectionInjection_Safe.java —— allowlist 类名映射，禁止反射任意类。
 */
package com.jsef.benchmark.vuln.reflectioninjection;

public class ReflectionInjection {

    // source：不可信类名/方法名
    public Object invokeUntrusted(String className, String methodName, Object... args) throws Exception {
        // [CHECKPOINT id=JSEF-REFLECT-001 cwe=470 level=L4 source=HttpServletRequest parameter sink=Method.invoke expect=VULN trace=benchmark/cases/vuln/reflection-injection/ReflectionInjection.java:21,benchmark/cases/vuln/reflection-injection/ReflectionInjection.java:24,benchmark/cases/vuln/reflection-injection/ReflectionInjection.java:26]
        // 危险：攻击者控制的类名经反射加载
        Class<?> clazz = Class.forName(className);
        // 危险：invoke 执行任意方法
        return clazz.getMethod(methodName).invoke(null, args);
    }
}
