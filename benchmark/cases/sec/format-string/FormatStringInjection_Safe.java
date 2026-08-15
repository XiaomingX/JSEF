/*
 * JSEF Benchmark 样本 — 格式串注入（安全对照）：固定格式串，不可信输入仅作参数（B1 组，CWE-134，L3）
 *
 * ① 子目标清单：
 *    - 演示如何修正格式串注入：格式模板必须是源码常量，不可信输入只作为填充参数。
 *    - 即使参数含 %x 等字符，也仅被当作字面量，不会触发格式转换。
 * ② 可达性说明：
 *    - TEMPLATE 为固定常量格式串；userArg 仅作为 %s 的参数传入。
 *    - 攻击者无法控制格式模板，注入的 % 序列被当作普通文本。
 * ③ 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 * ④ 修复要点：固定格式串常量 + 不可信输入仅作参数。
 */
package com.jsef.benchmark.sec.formatstring;

public class FormatStringInjection_Safe {

    // 固定格式模板（源码常量）
    private static final String TEMPLATE = "Hello %s, you have %d messages";

    public String formatTrusted(String userArg, int count) {
        // 修复：格式串固定，不可信输入仅作参数
        // [CHECKPOINT id=JSEF-FMT-001S cwe=134 level=L3 source=HttpServletRequest parameter sink=String.format(fixedTemplate, args) expect=SAFE trace=benchmark/cases/sec/format-string/FormatStringInjection_Safe.java:18,benchmark/cases/sec/format-string/FormatStringInjection_Safe.java:23]
        return String.format(TEMPLATE, userArg, count);
    }
}
