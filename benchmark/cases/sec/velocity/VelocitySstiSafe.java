package com.jsef.benchmark.sec;

import java.io.StringWriter;

/*
 * JSEF-Benchmark L2 — Velocity SSTI 修复（CWE-1336）
 *
 * 修复：模板固定为常量，用户值仅以变量形式放入上下文，绝不作为模板源码。
 *
 * CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine)。
 */
public class VelocitySstiSafe {

    static final String FIXED_TPL = "Hello $name!"; // 常量模板

    static void render(String tmpl, java.util.Map<String, Object> ctx) {
        System.out.println("[velocity-eval] " + tmpl);
    }

    /**
     * 安全路径：模板固定，用户输入仅作数据。
     *
     * @param userInput 用户可控数据
     */
    public void render(String userInput, java.util.Map<String, Object> ctx) {
        java.util.Map<String, Object> safe = new java.util.HashMap<>(ctx);
        safe.put("name", userInput); // 用户输入仅作为数据变量
        StringWriter w = new StringWriter();
        // [CHECKPOINT id=JSEF-NV108S cwe=1336 level=L2 source=userInput sink=VelocityEngine.evaluate (fixed template, input as data only) expect=SAFE]
        render(FIXED_TPL, safe); // 模板固定，不可被用户输入改变
    }

    public static void main(String[] args) {
        new VelocitySstiSafe().render("<script>", java.util.Map.of());
    }
}
