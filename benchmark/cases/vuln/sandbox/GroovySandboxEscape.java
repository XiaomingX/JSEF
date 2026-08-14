package com.jsef.benchmark.vuln;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * JSEF-Benchmark L5 — 沙箱逃逸 / Sandbox Escape（借鉴 VulnGym 传统类 Sandbox Escape）
 *
 * 难度：L5（gadget chain 级）。抽象模拟 Apache Groovy {@code SecureASTCustomizer}
 * 沙箱被绕过：配置看似用了 AST 黑名单 + 类型限制，但攻击者借助"元编程"手段
 * （如 {@code this.class}、闭包委托、{@code @AST} 变换或方法_missing 元数据）逃出受限 AST，
 * 在语法树检查通过后、运行时再解析出 {@code Runtime.exec} 可达性。
 *
 * 关键点：每个单独组件都"安全"——AST 黑名单拦截了直接 {@code Runtime} 字面量、
 * 类型白名单限制了可实例化的类。但当受限脚本通过元编程在运行时动态构造调用目标时，
 * 静态 AST 检查（编译期）无法覆盖运行时行为，组合后形成逃逸链。
 * 需跨"编译期 AST 校验 + 运行时元编程"两阶段的可达性分析，纯语法 SAST 难识别。
 *
 * 用标准库（Map / Function / 简单符号表）模拟 Groovy 编译期校验 + 运行时求值，
 * 不依赖 Groovy 第三方库。
 *
 * CWE-265 Privilege / Sandbox Issues（沙箱配置可被绕过语义）。
 *
 * 安全底线：仅 localhost 演示语义，不提供真实 Groovy 逃逸利用脚本/载荷。
 */
public class GroovySandboxEscape {

    /** 模拟 AST 黑名单：编译期拦截的危险方法名。 */
    private static final Set<String> AST_BLACKLIST = new HashSet<>(Arrays.asList("exec", "Runtime"));
    /** 模拟类型白名单：编译期允许实例化的类。 */
    private static final Set<String> TYPE_WHITELIST = new HashSet<>(Arrays.asList("String", "Integer", "List"));

    /** 极简符号表：运行时变量绑定（元编程可调用的跳板）。 */
    static class Scope {
        final java.util.Map<String, Object> vars = new java.util.HashMap<>();
        Object get(String k) { return vars.get(k); }
        void set(String k, Object v) { vars.put(k, v); }
    }

    /**
     * 模拟 SecureASTCustomizer 编译期校验：仅检查 AST 字面量是否在黑名单。
     * 返回 true 表示"看似通过"，但无法覆盖运行时元编程构造的目标。
     */
    static boolean astCheckPasses(String scriptAstToken) {
        // 编译期只看字面量，漏掉元编程动态构造的调用
        for (String banned : AST_BLACKLIST) {
            if (scriptAstToken.contains(banned)) return false;
        }
        return true; // 看似通过：脚本未直写 "exec"/"Runtime"
    }

    /**
     * 模拟运行时求值：受限脚本通过元编程（this.class / 闭包委托）动态取得 Runtime。
     *
     * @param untrustedScript 不可信脚本（污点 source）
     */
    public static Object evalViaMetaProgramming(String untrustedScript) {
        Scope scope = new Scope();
        // 沙箱"看似安全"：AST 黑名单拦截了直接危险字面量
        if (!astCheckPasses(untrustedScript)) {
            throw new SecurityException("AST blacklist blocked (static)");
        }

        // 元编程跳板：沙箱内允许的对象被脚本当作起点，运行时反射拿 Runtime
        scope.set("pivot", "localhost-demo");

        // 危险 sink：运行时经元编程/反射逃逸 AST 限制，调用 Runtime.exec
        // [CHECKPOINT id=JSEF-V2-002 cwe=265 level=L5 source=untrustedScript sink=Runtime.getRuntime().exec(meta-programming) expect=VULN trace=benchmark/cases/vuln/sandbox/GroovySandboxEscape.java:63,benchmark/cases/vuln/sandbox/GroovySandboxEscape.java:68,benchmark/cases/vuln/sandbox/GroovySandboxEscape.java:82]
        return escapeThroughMeta(scope, "echo localhost-demo");
    }

    /**
     * 抽象模拟"元编程逃逸"：从受控 pivot 对象经反射到达 Runtime.exec。
     * 编译期 AST 校验看不到此运行时路径，故被判定"通过"——实则逃逸。
     */
    static Object escapeThroughMeta(Scope scope, String command) {
        try {
            Object pivot = scope.get("pivot");
            Class<?> runtimeClass = Class.forName("java.lang.Runtime");
            java.lang.reflect.Method getRuntime = runtimeClass.getMethod("getRuntime");
            Object runtime = getRuntime.invoke(null);
            java.lang.reflect.Method exec = runtimeClass.getMethod("exec", String.class);
            return exec.invoke(runtime, command);
        } catch (Exception e) {
            throw new RuntimeException("groovy meta-programming escape (demo only)", e);
        }
    }

    public static void main(String[] args) {
        // 仅演示逃逸可达性语义；脚本不含字面量黑名单词，编译期通过、运行时逃逸
        evalViaMetaProgramming("def x = pivot; x");
    }
}
