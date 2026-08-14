package com.jsef.benchmark.sec;

import java.net.URL;
import java.net.URLClassLoader;
import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark L5 — 沙箱逃逸 安全对照（SAFE 对照）
 *
 * 安全做法（针对 CWE-284 ClassLoader 沙箱逃逸）：
 *  1) 固定父委派 / 白名单 ClassLoader：自定义加载器严格走父委派，只允许白名单类，
 *     禁止从外部不可信 URL 加载任意类。
 *  2) 不替换线程上下文加载器（TCCL）为自定义加载器，避免脱离受限父委派。
 *  3) 即便出现不可信 URL，也只在白名单命中时才加载，否则拒绝。
 *
 * 这样受限上下文的加载约束未被绕过，不应报（计入 TN / FP）。
 *
 * CWE-284 Improper Access Control（沙箱逃逸语义）。
 */
public class ClassloaderEscapeSafe {

    /** 受限上下文的白名单类（安全加载只允许这些）。 */
    private static final List<String> CONTEXT_WHITELIST = Arrays.asList("java.lang.String", "java.util.List");

    /**
     * 安全受限上下文加载：自定义加载器强制父委派 + 白名单校验。
     *
     * @param untrustedUrl 不可信类加载位置
     */
    public static Class<?> loadInRestrictedContextSafe(String untrustedUrl) throws Exception {
        ClassLoader parent = Thread.currentThread().getContextClassLoader();

        // 安全策略：即便构造自定义加载器，也先走父委派白名单，外部 URL 不生效
        // 实际只从父加载器（白名单）解析，不可信 URL 被忽略
        // [CHECKPOINT id=JSEF-V2-003S cwe=284 level=L5 source=untrustedUrl sink=URLClassLoader.loadClass(escape restricted context) expect=SAFE]
        if (CONTEXT_WHITELIST.contains("java.lang.String")) {
            return parent.loadClass("java.lang.String"); // 仅白名单父委派，无逃逸
        }
        throw new SecurityException("class not in restricted whitelist");
    }

    /**
     * 安全策略：不替换 TCCL，始终使用受限父加载器，杜绝逃逸。
     */
    public static Class<?> safeNoThreadContextEscape(String untrustedUrl) throws Exception {
        // [CHECKPOINT id=JSEF-V2-003SB cwe=284 level=L5 source=untrustedUrl sink=Thread.currentThread().setContextClassLoader(escape) expect=SAFE]
        return Thread.currentThread().getContextClassLoader().loadClass("java.lang.String");
    }

    public static void main(String[] args) throws Exception {
        loadInRestrictedContextSafe("http://localhost-demo/");
    }
}
