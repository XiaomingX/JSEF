package com.jsef.benchmark.sec;

/**
 * JSEF-Benchmark Phase5-D — 日志注入安全版（CWE-93，难度 L2）
 *
 * 与 LogInjectionCrlf 对照：写入日志前转义/剥离 CRLF 等控制字符，
 * 防止日志行被拆分伪造，是真正的 SAFE，用于计算 TN / 误报（FP）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实伪造日志脚本。
 */
public class LogInjectionCrlfSafe {

    static void log(String userMsg) {
        // 剥离换行与回车，防止日志注入
        String safe = userMsg.replaceAll("[\\r\\n]", "");
        // [CHECKPOINT id=JSEF-CX-001S cwe=93 level=L2 source=user-controlled message sink=logger.info (sanitized) expect=SAFE]
        System.out.println("[AUDIT] " + safe); // 已转义，无法拆分日志行
    }
}
