package com.jsef.benchmark.vuln;

import java.lang.reflect.Method;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

/**
 * JSEF-Benchmark L4 — 沙箱逃逸 / Sandbox Escape（借鉴 VulnGym 传统类 Sandbox Escape）
 *
 * 难度：L4（跨方法 / 框架语义）。沙箱本意通过受限 ScriptEngine 环境约束脚本能力，
 * 但脚本内部通过反射（{@code getClass().forName("java.lang.Runtime")}）绕过沙箱限制，
 * 拿到 {@code Runtime.getRuntime().exec} 形成代码执行可达性。
 *
 * 关键点：沙箱 API（ScriptEngine.eval）本身看似被"限制"，但污点（不可信脚本）一旦进入
 * 引擎，脚本体可利用反射脱离沙箱语义边界——纯语法 SAST 只看到 eval 调用，需识别
 * "沙箱约束 + 反射越界"组合才判定为逃逸。
 *
 * CWE-284 Improper Access Control（沙箱逃逸语义）。
 *
 * 安全底线：仅 localhost 演示语义，不提供真实逃逸利用脚本/载荷。
 */
public class ScriptEngineSandboxEscape {

    /**
     * 受限沙箱外的脚本入口：不可信脚本被送入 ScriptEngine，沙箱"以为"已受限。
     *
     * @param untrustedScript 不可信脚本内容（污点 source）
     */
    public static Object runInSandbox(String untrustedScript) throws ScriptException {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("js");

        // 沙箱"看似受限"：仅暴露有限绑定对象，未禁止反射
        // 危险 sink：脚本内部可通过反射拿到 Runtime，逃逸沙箱约束
        // [CHECKPOINT id=JSEF-V2-001 cwe=284 level=L4 source=untrustedScript sink=Runtime.getRuntime().exec(exec via reflection) expect=VULN trace=benchmark/cases/vuln/sandbox/ScriptEngineSandboxEscape.java:46,benchmark/cases/vuln/sandbox/ScriptEngineSandboxEscape.java:56]
        return engine.eval(untrustedScript);
    }

    /**
     * 抽象模拟"脚本内部反射越界"：沙箱外的代码通过 Class/Method 反射调用 Runtime.exec。
     * 标准库模拟（不依赖真实引擎/沙箱库），表达"看似受限实则可达"的逃逸语义。
     *
     * @param sandboxBoundValue 沙箱内可访问的受控对象（被脚本当作反射跳板）
     */
    public static Object reflectOutOfSandbox(Object sandboxBoundValue, String command) {
        try {
            // 沙箱约束被反射绕过：从任意对象出发拿到 java.lang.Runtime
            Method getClass = Object.class.getMethod("getClass");
            Class<?> runtimeClass = Class.forName("java.lang.Runtime");
            Method getRuntime = runtimeClass.getMethod("getRuntime");
            Object runtime = getRuntime.invoke(null);

            // 危险 sink：反射驱动 Runtime.exec —— 沙箱限制被突破
            // [CHECKPOINT id=JSEF-V2-001B cwe=284 level=L4 source=sandboxBoundValue(reflection pivot) sink=Runtime.getRuntime().exec expect=VULN trace=benchmark/cases/vuln/sandbox/ScriptEngineSandboxEscape.java:49,benchmark/cases/vuln/sandbox/ScriptEngineSandboxEscape.java:50,benchmark/cases/vuln/sandbox/ScriptEngineSandboxEscape.java:51]
            Method exec = runtimeClass.getMethod("exec", String.class);
            return exec.invoke(runtime, command);
        } catch (Exception e) {
            throw new RuntimeException("sandbox reflection escape (demo only)", e);
        }
    }

    public static void main(String[] args) throws Exception {
        // 仅演示逃逸可达性语义，command 为 localhost 演示占位，不连接真实目标
        reflectOutOfSandbox("localhost-demo", "echo localhost-demo");
    }
}
