package com.jsef.benchmark.vuln;

import java.net.URL;
import java.net.URLClassLoader;
import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark L5 — 沙箱逃逸 / Sandbox Escape（借鉴 VulnGym 传统类 Sandbox Escape）
 *
 * 难度：L5（跨文件 / 框架语义 / 状态机）。模拟受限执行上下文（如插件沙箱、受限线程）
 * 通过"自定义 ClassLoader"或"线程上下文加载器（TCCL）"逃逸：受限上下文本应只允许
 * 加载白名单内的安全类，但代码借助自定义 {@code URLClassLoader} / 线程上下文加载器
 * 从外部 URL 加载任意类（含危险类），从而突破受限边界、获得代码执行可达性。
 *
 * 关键点：受限上下文的"加载约束"被自定义加载器绕过——标准 {@code ClassLoader.loadClass}
 * 受父委派白名单限制，但自定义加载器直接走 {@code URLClassLoader} 从不可信位置加载字节，
 * 污点（不可信 URL）驱动加载危险类。需跨"上下文约束 + 自定义加载器语义"识别逃逸。
 *
 * 用标准库（{@code URLClassLoader} 抽象）模拟"自定义加载器逃逸"，不依赖第三方沙箱库。
 *
 * CWE-284 Improper Access Control（沙箱逃逸语义）。
 *
 * 安全底线：仅 localhost 演示语义，不提供真实逃逸利用脚本/载荷。
 */
public class ClassloaderEscape {

    /** 受限上下文的白名单类（语义约束：只允许这些）。 */
    private static final List<String> CONTEXT_WHITELIST = Arrays.asList("java.lang.String", "java.util.List");

    /**
     * 受限上下文入口：不可信 URL 作为加载源（污点 source）。
     *
     * @param untrustedUrl 不可信类加载位置（污点）
     */
    public static Class<?> loadInRestrictedContext(String untrustedUrl) throws Exception {
        // 受限上下文"看似"限制加载，但代码改用自定义 URLClassLoader 逃逸
        ClassLoader restricted = Thread.currentThread().getContextClassLoader();

        // 危险 sink：自定义加载器从不可信 URL 直接加载任意类，突破受限白名单
        // [CHECKPOINT id=JSEF-V2-003 cwe=284 level=L5 source=untrustedUrl sink=URLClassLoader.loadClass(escape restricted context) expect=VULN]
        URLClassLoader escapeLoader = new URLClassLoader(new URL[]{ new URL(untrustedUrl) }, restricted);
        return escapeLoader.loadClass("java.lang.Runtime"); // 危险类被逃逸加载
    }

    /**
     * 抽象模拟"线程上下文加载器替换"逃逸：把 TCCL 替换为自定义加载器后加载危险类。
     */
    public static Class<?> escapeViaThreadContext(String untrustedUrl) throws Exception {
        ClassLoader original = Thread.currentThread().getContextClassLoader();
        try {
            // 危险 sink：替换 TCCL 为自定义加载器，脱离受限父委派
            // [CHECKPOINT id=JSEF-V2-003B cwe=284 level=L5 source=untrustedUrl sink=Thread.currentThread().setContextClassLoader(escape) expect=VULN]
            URLClassLoader custom = new URLClassLoader(new URL[]{ new URL(untrustedUrl) }, null);
            Thread.currentThread().setContextClassLoader(custom);
            return custom.loadClass("java.lang.Runtime");
        } finally {
            Thread.currentThread().setContextClassLoader(original);
        }
    }

    public static void main(String[] args) throws Exception {
        // 仅演示加载可达性语义；URL 为 localhost 占位，不连接真实外部目标
        System.out.println("[classloader-escape-demo] " + CONTEXT_WHITELIST);
    }
}
