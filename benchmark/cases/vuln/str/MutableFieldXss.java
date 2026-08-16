/*
 * JSEF Benchmark — FP 混淆型安全样本的对照 vuln（CWE-79, 难度 L4）
 *
 * 对照样本：可变字段未经校验直接拼入 HTML 输出，可 XSS。
 * 与 RecordValidatedSafe 的构造期校验 record 形成 vuln/safe 对。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.vuln;

public class MutableFieldXss {

    /**
     * 危险入口：name 字段可变且未校验，直接拼入 HTML 输出。
     * @param rawName 不可信用户输入（如 "<script>alert(1)</script>"）
     */
    static String unsafe(String rawName) {
        String name = rawName;
        String out = "<span>" + name + "</span>";
        // [CHECKPOINT id=JSEF-FP-006V cwe=79 level=L4 source=rawName sink=response output expect=VULN]
        return out;
    }
}
