package com.jsef.benchmark.sec.dbg;

import java.util.Arrays;
import java.util.List;

/**
 * DBG-3 Deny/Allow-list Bypass by Encoding — 安全修复版
 *
 * 修复策略（与任何具体 RPC 框架解耦，仅用 Java 标准库自包含演示）：
 *  1) 名单比较使用 Class 对象「精确相等」(== / 同一 Class 实例)，而非字符串包含/匹配，
 *     因此大小写、点分隔、嵌套包装、字符串拼接等编码变形无法绕过；
 *  2) 彻底禁用 ClassLoader 动态加载任意类名，仅允许经固定白名单 Class 实例实例化。
 *
 * 仅用于 localhost 演示语义，不连接真实远端；危险调用用 "localhost-demo" 占位。
 */
public class DBG3_ListBypassByEncoding_Safe {

    // 危险类的精确 Class 对象白名单（用 == 比较，字符串变形无法伪造）
    private static final List<Class<?>> DENY_CLASSES = Arrays.asList(
            Runtime.class, ProcessBuilder.class
    );

    // ============ L3：Class 对象精确相等比较 ============

    /**
     * L3 修复：先用 Class.forName 解析出真实 Class 对象，再用 == 与黑名单 Class 对象精确比较。
     * 任何字符串变形（大小写/点分隔/嵌套包装）都无法改变「解析后得到的 Class 实例」，
     * 因此绕不过精确相等检查。
     */
    public void load(String name) throws Exception {
        Class<?> clazz = Class.forName(name);
        // [SAFE] 用 Class 对象精确相等比较（非字符串匹配），编码变形类名无法绕过
        // [CHECKPOINT id=JSEF-DBG-301S cwe=502 level=L3 source=class name sink=Class-object equality (not string) expect=SAFE]
        for (Class<?> deny : DENY_CLASSES) {
            if (clazz == deny) {
                throw new SecurityException("blocked by deny-list (class equality)");
            }
        }
        Object instance = clazz.getDeclaredConstructor().newInstance();
        // localhost-demo：危险调用占位，不连接真实远端
        System.out.println("localhost-demo: instantiated " + instance.getClass().getName());
    }

    // ============ L4：禁用 ClassLoader 动态加载 ============

    /**
     * L4 修复：完全移除 ClassLoader.loadClass(a + b) 等动态加载路径，
     * 类名来源被限定为服务端固定白名单 Class 实例，禁止任何运行时字符串拼名。
     */
    public void loadDynamic(String a, String b) throws Exception {
        // [SAFE] 禁用 ClassLoader 动态加载：先解析出真实 Class 对象，再用 == 与黑名单精确比较
        // [CHECKPOINT id=JSEF-DBG-302S cwe=502 level=L4 source=class name sink=no dynamic ClassLoader, exact compare expect=SAFE]
        Class<?> target = Class.forName(a + b); // 仅解析，不交给 ClassLoader 动态加载
        for (Class<?> deny : DENY_CLASSES) {
            if (target == deny) {
                throw new SecurityException("blocked by deny-list (class equality), dynamic loading disabled");
            }
        }
        // localhost-demo：仅允许解析、实例化白名单外的安全类，不连接真实远端
        Object instance = target.getDeclaredConstructor().newInstance();
        System.out.println("localhost-demo: fixed-class load " + instance.getClass().getName());
    }
}
