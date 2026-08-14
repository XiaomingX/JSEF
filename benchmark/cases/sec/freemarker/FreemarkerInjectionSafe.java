/*
 * JSEF Benchmark 样本 — Freemarker 模板注入安全对照（CWE-94，L3）
 * 禁用 ?api / ?new 危险内建，用户输入仅作数据模型渲染。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

public class FreemarkerInjectionSafe {

    interface Template { String process(String templateContent, Object model); }

    // 固定模板，仅引用数据模型字段
    static final String SAFE_TEMPLATE = "<p>\${userContent}</p>";

    // [SAFE] 模板固定，用户输入仅作数据，危险内建已禁用
    static String render(Template engine, String userInput) {
        // [CHECKPOINT id=JSEF-FM-001S cwe=94 level=L3 source=userInput (data model) sink=freemarker Template.process (fixed template, api disabled) expect=SAFE]
        return engine.process(SAFE_TEMPLATE, userInput);   // 模板固定 → 无注入
    }
}
