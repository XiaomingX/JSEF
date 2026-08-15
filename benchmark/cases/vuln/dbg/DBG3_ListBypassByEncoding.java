package com.jsef.benchmark.vuln.dbg;

/**
 * DBG-3 Deny/Allow-list Bypass by Encoding (RPC 机制 DBG 原子范式 —— 名单编码绕过子类)
 *
 * 对应 CVE-2023-23638 的「类名/类型黑名单靠字符串匹配，攻击者对危险类名做编码/变形
 * 绕过匹配」这一独立子维度。本文件与任何具体 RPC 框架完全解耦，
 * 仅用 Java 标准库（Class.forName / ClassLoader / Method.invoke 等）自包含演示。
 *
 * 维度边界：聚焦「黑名单被编码/变形绕过」（大小写、点分隔、嵌套包装、字符串拼接、反射拼名），
 * 与 JSEF-DESER-*（直接 readObject）、JSEF-TCM-*（类型混淆 / 缓存二次解析绕过）不重叠。
 *
 * 仅用于 localhost 演示语义，不连接真实远端，不提供可利用的载荷脚本；
 * 所有危险调用均用 "localhost-demo" 占位。
 */
public class DBG3_ListBypassByEncoding {

    // 危险类名的字符串黑名单（仅用于演示字符串匹配型防护的脆弱性）
    private static final String[] DENY_LIST = {"runtime", "processbuilder", "exec"};

    // ============ L3：单方法内编码/变形绕过黑名单 ============

    /**
     * L3 方法混淆（间接/跨方法语义，单方法内完成）：
     * 黑名单用 name.toLowerCase().contains(...) 字符串匹配拒绝；
     * 攻击者传入 "RuNtImE"（大小写）/"Ru.ntime"（点分隔变形）/嵌套包装 "Wrapper$Runtime"
     * 均可绕过 contains 匹配，最终 newInstance() 实例化危险类。
     */
    public void load(String name) throws Exception {
        // 行1：黑名单检查被绕过点 —— 攻击者传入变形类名使字符串匹配失败
        boolean blocked = false;
        for (String deny : DENY_LIST) {
            if (name.toLowerCase().contains(deny)) {
                blocked = true;
                break;
            }
        }
        if (blocked) {
            throw new SecurityException("blocked by deny-list");
        }
        // [VULN] 变形类名绕过字符串黑名单后，被当作合法类名加载实例化
        // [CHECKPOINT id=JSEF-DBG-301 cwe=502 level=L3 source=encoded/obfuscated class name sink=Class.forName(bypassed).newInstance() expect=VULN trace=benchmark/cases/vuln/dbg/DBG3_ListBypassByEncoding.java:33,benchmark/cases/vuln/dbg/DBG3_ListBypassByEncoding.java:45]
        String resolved = name.replace(".", ""); // 去掉点分隔变形
        Class<?> clazz = Class.forName(resolved);
        Object instance = clazz.newInstance();
        // localhost-demo：危险调用占位，不连接真实远端
        System.out.println("localhost-demo: instantiated " + instance.getClass().getName());
    }

    // ============ L4：字符串拼接 / 反射拼名跨节点绕过 ============

    /**
     * L4 方法混淆（跨节点：拼接点 -> 加载点）：
     * 黑名单匹配「精确类名」，攻击者用 ClassLoader.loadClass(a + b) 字符串拼接
     * （"java.lang.Run" + "time"）或 getClass().getClassLoader().loadClass(resolved)
     * 反射拼名绕过精确匹配，最终加载危险类。
     */
    public void loadDynamic(String a, String b) throws Exception {
        // 行1：拼接点 —— 攻击者将危险类名拆成两段拼回，绕过精确字符串匹配
        String resolved = a + b;
        // [VULN] 拼接出的危险类名绕过精确黑名单后，经 ClassLoader 动态加载
        // [CHECKPOINT id=JSEF-DBG-302 cwe=502 level=L4 source=string-concat class name sink=ClassLoader.loadClass/forName(bypassed) expect=VULN trace=benchmark/cases/vuln/dbg/DBG3_ListBypassByEncoding.java:60,benchmark/cases/vuln/dbg/DBG3_ListBypassByEncoding.java:64]
        ClassLoader cl = getClass().getClassLoader();
        Class<?> clazz = cl.loadClass(resolved);
        Object instance = clazz.getDeclaredConstructor().newInstance();
        // localhost-demo：危险调用占位，不连接真实远端
        System.out.println("localhost-demo: dynamically loaded " + instance.getClass().getName());
    }
}
