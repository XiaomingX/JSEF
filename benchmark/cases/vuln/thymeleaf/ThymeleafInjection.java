/*
 * JSEF Benchmark 样本 — Thymeleaf 模板注入（CWE-94，L3）
 * 视图名 / 片段由用户输入拼接，触发 SpEL 解析。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

public class ThymeleafInjection {

    // 演示用视图解析接口（语义同 Spring Thymeleaf ViewResolver)
    interface ViewResolver { String resolve(String viewName); }

    // [VULN] 用户输入拼接为视图名，触发 SpEL 解析
    static String render(ViewResolver resolver, String userInput) {
        // source：不可信用户输入（HTTP 请求参数，拼接为 view name）
        // [CHECKPOINT id=JSEF-THYME-001 cwe=94 level=L3 source=userInput (view name) sink=Thymeleaf ViewResolver.resolve (SpEL) expect=VULN]
        return resolver.resolve(userInput);   // 用户输入即视图名 → SpEL 注入
    }
}
