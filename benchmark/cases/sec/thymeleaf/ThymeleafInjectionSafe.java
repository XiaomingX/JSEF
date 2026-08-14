/*
 * JSEF Benchmark 样本 — Thymeleaf 模板注入安全对照（CWE-94，L3）
 * 固定 view name + 转义文本（th:text），用户输入仅作数据。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

public class ThymeleafInjectionSafe {

    interface ViewResolver { String resolve(String viewName, Object model); }

    static final String SAFE_VIEW = "home";   // 固定视图名

    // [SAFE] 视图名固定，用户输入仅作转义后的数据
    static String render(ViewResolver resolver, String userInput) {
        // [CHECKPOINT id=JSEF-THYME-001S cwe=94 level=L3 source=userInput (data only) sink=Thymeleaf ViewResolver.resolve (fixed view) expect=SAFE]
        return resolver.resolve(SAFE_VIEW, userInput);   // 视图名固定 → 无注入
    }
}
