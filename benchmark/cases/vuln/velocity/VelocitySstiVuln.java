package com.jsef.benchmark.vuln;

import java.io.StringWriter;

/*
 * JSEF-Benchmark L2 — Velocity 服务端模板注入（CWE-1336）
 *
 * 难度：L2（多跳）。把用户可控字符串作为模板源码交给 VelocityEngine.evaluate，
 * 攻击者可注入 #set / #foreach 等指令执行任意逻辑。
 *
 * CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用模板。
 *
 * 修复要点（对照 VelocitySstiSafe.java）：模板固定，用户输入仅作数据。
 */
public class VelocitySstiVuln {

    // 抽象 sink：语义等价 org.apache.velocity.VelocityEngine.evaluate(ctx, w, name, tmpl)
    static void render(String tmpl, java.util.Map<String, Object> ctx) {
        System.out.println("[velocity-eval] " + tmpl);
    }

    /**
     * 危险路径：用户字符串即模板。
     *
     * @param userInput 用户可控模板
     */
    public void render(String userInput, java.util.Map<String, Object> ctx) {
        StringWriter w = new StringWriter();
        // [CHECKPOINT id=JSEF-NV108 cwe=1336 level=L2 source=userInput sink=VelocityEngine.evaluate expect=VULN]
        render(userInput, ctx); // 用户输入直接作为模板源码求值
    }

    public static void main(String[] args) {
        new VelocitySstiVuln().render("#set($x = 1) $x", java.util.Map.of());
    }
}
