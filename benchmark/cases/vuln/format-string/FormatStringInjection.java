/*
 * JSEF Benchmark 样本 — 格式串注入：不可信格式串 String.format（B1 组，CWE-134，L3）
 *
 * ① 子目标清单：
 *    - 演示"格式串注入"：攻击者控制 format 模式的第一个参数，可读取栈上其他参数/越界访问。
 *    - 展示 source（请求参数）→ sink（String.format）跨越信任边界。
 *    - 让静态分析识别"格式串本身来自不可信输入"。
 * ② 可达性说明：
 *    - source：HTTP 请求参数 userFmt（来自客户端，不可信）。
 *    - sink：String.format(userFmt, args) 以不可信串作为格式模板。
 *    - data flow：userFmt 不经校验直接作为格式串，可注入 %x/%s/%n 等转换符。
 * ③ 安全底线：仅 localhost 演示语义，不写真实利用脚本，不提供信息泄露 payload。
 * ④ 修复要点：见 sec 文件 FormatStringInjection_Safe.java —— 固定格式串，不可信输入仅作参数。
 */
package com.jsef.benchmark.vuln.formatstring;

public class FormatStringInjection {

    // source：不可信格式串直接来自请求参数
    public String formatUntrusted(String userFmt, Object... args) {
        // [CHECKPOINT id=JSEF-FMT-001 cwe=134 level=L3 source=HttpServletRequest parameter sink=String.format(taintedFmt, args) expect=VULN trace=benchmark/cases/vuln/format-string/FormatStringInjection.java:20,benchmark/cases/vuln/format-string/FormatStringInjection.java:23]
        // 危险：格式串本身由攻击者控制
        return String.format(userFmt, args);
    }
}
