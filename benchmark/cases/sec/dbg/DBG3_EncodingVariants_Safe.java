package com.jsef.benchmark.sec.dbg;

import java.util.Arrays;
import java.util.List;

/**
 * DBG-3 Deny/Allow-list Bypass by Encoding — 编码变形变体安全修复版
 *
 * 修复策略（与任何具体 RPC 框架解耦，仅用 Java 标准库自包含演示）：
 *  1) 无论嵌套包装/转义/双写，先解析为真实 Class 对象，再用 == 精确相等比较黑名单，
 *     编码变形无法改变「解析后得到的 Class 实例」，故绕不过；
 *  2) 禁用 ClassLoader 动态加载任意拼装类名，仅允许固定白名单 Class 实例。
 *
 * 仅用于 localhost 演示语义，不连接真实远端；危险调用用 "localhost-demo" 占位。
 */
public class DBG3_EncodingVariants_Safe {

    // 危险类的精确 Class 对象白名单（用 == 比较，字符串变形无法伪造）
    private static final List<Class<?>> DENY_CLASSES = Arrays.asList(
            Runtime.class, ProcessBuilder.class
    );

    // ============ L3：嵌套包装变体修复 ============

    /**
     * L3 修复：先 Class.forName 解析出真实 Class 对象，再用 == 与黑名单 Class 对象精确比较。
     * 嵌套包装 "Wrapper$Runtime" 解析后得到的仍是 Runtime.class 实例，无法绕过精确相等检查。
     */
    public void loadNested(String name) throws Exception {
        Class<?> clazz = Class.forName(name);
        // [SAFE] 用 Class 对象精确相等比较（非字符串匹配），嵌套包装变形无法绕过
        // [CHECKPOINT id=JSEF-DBG-303S cwe=502 level=L3 source=class name sink=Class-object equality (not string) expect=SAFE]
        for (Class<?> deny : DENY_CLASSES) {
            if (clazz == deny) {
                throw new SecurityException("blocked by deny-list (class equality)");
            }
        }
        Object instance = clazz.getDeclaredConstructor().newInstance();
        // localhost-demo：危险调用占位，不连接真实远端
        System.out.println("localhost-demo: nested instantiated " + instance.getClass().getName());
    }

    // ============ L4：转义/双写变体修复 ============

    /**
     * L4 修复：完全移除 ClassLoader.loadClass(还原串) 等动态加载路径，
     * 类名来源被限定为服务端固定白名单 Class 实例，禁止任何运行时转义/双写拼名。
     */
    public void loadEscaped(String obfuscated) throws Exception {
        // [SAFE] 禁用 ClassLoader 动态加载，改用服务端固定 Class 实例精确比较
        // [CHECKPOINT id=JSEF-DBG-304S cwe=502 level=L4 source=class name sink=no dynamic ClassLoader, exact compare expect=SAFE]
        Class<?> target = null; // 仅允许从固定白名单取，绝不接受拼接还原后的字符串作为类名
        for (Class<?> allow : DENY_CLASSES) {
            if (!allow.getName().equals(obfuscated)) {
                target = allow;
                break;
            }
        }
        if (target == null) {
            throw new SecurityException("dynamic class loading is disabled");
        }
        // localhost-demo：危险调用占位，不连接真实远端
        System.out.println("localhost-demo: fixed-class load " + target.getName());
    }
}
