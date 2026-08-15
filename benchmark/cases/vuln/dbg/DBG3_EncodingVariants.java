package com.jsef.benchmark.vuln.dbg;

/**
 * DBG-3 Deny/Allow-list Bypass by Encoding — 编码变形变体（嵌套包装 / 转义 / 双写）
 *
 * 与 DBG3_ListBypassByEncoding 同属「名单编码绕过」独立子维度，但聚焦另外两类编码变形：
 *  - 嵌套包装：黑名单匹配平面类名，攻击者用 "Wrapper$Runtime"（内部类/嵌套包装）绕过；
 *  - 转义/双写：黑名单匹配原文，攻击者用转义字符或双写插入不可见字符使 contains 失效。
 * 与任何具体 RPC 框架完全解耦，仅用 Java 标准库自包含演示。
 *
 * 仅用于 localhost 演示语义，不连接真实远端；危险调用用 "localhost-demo" 占位。
 */
public class DBG3_EncodingVariants {

    // 危险类名的平面字符串黑名单（演示字符串匹配型防护的脆弱性）
    private static final String[] DENY_LIST = {"runtime", "processbuilder"};

    // ============ L3：嵌套包装变体 ============

    /**
     * L3 方法混淆（间接语义）：黑名单用 name.toLowerCase().contains("runtime") 平面匹配，
     * 攻击者传入 "shell.Wrapper$Runtime" 这种嵌套包装形式，contains("runtime") 在部分实现
     * 中被误判为不匹配（或匹配到包装类而非危险类），最终 newInstance() 实例化危险类。
     */
    public void loadNested(String name) throws Exception {
        // 行1：黑名单检查被绕过点 —— 嵌套包装使平面字符串匹配失效
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
        // [VULN] 嵌套包装类名绕过平面黑名单后，被加载实例化
        // [CHECKPOINT id=JSEF-DBG-303 cwe=502 level=L3 source=nested/obfuscated class name sink=Class.forName(bypassed).newInstance() expect=VULN trace=benchmark/cases/vuln/dbg/DBG3_EncodingVariants.java:29,benchmark/cases/vuln/dbg/DBG3_EncodingVariants.java:40]
        Class<?> clazz = Class.forName(name);
        Object instance = clazz.newInstance();
        // localhost-demo：危险调用占位，不连接真实远端
        System.out.println("localhost-demo: nested instantiated " + instance.getClass().getName());
    }

    // ============ L4：转义/双写变体 ============

    /**
     * L4 方法混淆（跨节点：转义拼装点 -> 加载点）：黑名单匹配"原始危险类名"，
     * 攻击者插入转义/不可见字符或双写（如 "Run\u200btime" / "Runtimetime" 删去中间重复）
     * 使字符串比较失效，ClassLoader 加载拼接还原后的类名。
     */
    public void loadEscaped(String obfuscated) throws Exception {
        // 行1：转义/双写还原点 —— 攻击者插入的不可见字符被删去，危险类名被拼回
        String resolved = obfuscated.replace("\u200b", "").replace("timetime", "time");
        // [VULN] 还原后的危险类名绕过精确黑名单后，经 ClassLoader 动态加载
        // [CHECKPOINT id=JSEF-DBG-304 cwe=502 level=L4 source=escape/double-write class name sink=ClassLoader.loadClass/forName(bypassed) expect=VULN trace=benchmark/cases/vuln/dbg/DBG3_EncodingVariants.java:54,benchmark/cases/vuln/dbg/DBG3_EncodingVariants.java:58]
        ClassLoader cl = getClass().getClassLoader();
        Class<?> clazz = cl.loadClass(resolved);
        Object instance = clazz.getDeclaredConstructor().newInstance();
        // localhost-demo：危险调用占位，不连接真实远端
        System.out.println("localhost-demo: escaped load " + instance.getClass().getName());
    }
}
