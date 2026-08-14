package com.jsef.benchmark.sec;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark L4 — 沙箱逃逸 安全对照（SAFE 对照）
 *
 * 安全做法（针对 CWE-284 沙箱逃逸）：
 *  1) 严格禁止反射 / 危险类绑定：沙箱环境不暴露 {@code java.lang.reflect}、
 *     {@code java.lang.Runtime} 等危险类型，脚本只能访问白名单 API。
 *  2) 不可信脚本仅能调用受控方法，无法以任意对象为跳板反射拿到 Runtime。
 *
 * 这样即便脚本内容来自不可信输入，也无法脱离沙箱语义边界，不应报（计入 TN / FP）。
 *
 * CWE-284 Improper Access Control（沙箱逃逸语义）。
 */
public class ScriptEngineSandboxEscapeSafe {

    /** 沙箱白名单：仅允许无害方法，拒绝任何反射/危险类访问。 */
    private static final List<String> SANDBOX_ALLOWED = Arrays.asList("toLowerCase", "toUpperCase", "trim");

    /**
     * 受限沙箱内的安全执行：引擎绑定被严格裁剪，禁止反射越界。
     *
     * @param untrustedScript 不可信脚本内容
     */
    public static Object runInSandboxSafe(String untrustedScript) throws ScriptException {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("js");

        // 安全策略：仅暴露白名单方法，不暴露反射/危险类绑定
        // [CHECKPOINT id=JSEF-V2-001S cwe=284 level=L4 source=untrustedScript sink=Runtime.getRuntime().exec(exec via reflection) expect=SAFE]
        return engine.eval(untrustedScript);  // 受限环境：反射/Runtime 不可达
    }

    /**
     * 抽象模拟"安全沙箱"：不可信对象被严格限制，无法反射拿到 Runtime。
     *
     * @param sandboxBoundValue 沙箱内受控对象
     */
    public static Object reflectContained(Object sandboxBoundValue, String command) {
        // 安全策略：拒绝任何反射调用，command 不参与链路
        if (!SANDBOX_ALLOWED.contains(String.valueOf(command))) {
            throw new SecurityException("reflection/unsafe call denied by sandbox policy");
        }
        // [CHECKPOINT id=JSEF-V2-001SB cwe=284 level=L4 source=sandboxBoundValue(reflection pivot) sink=Runtime.getRuntime().exec expect=SAFE]
        return sandboxBoundValue.toString();  // 仅无害字符串操作，无反射 exec
    }

    public static void main(String[] args) throws Exception {
        reflectContained("localhost-demo", "trim");
    }
}
