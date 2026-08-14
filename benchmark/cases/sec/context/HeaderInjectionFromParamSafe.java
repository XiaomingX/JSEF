package com.jsef.benchmark.sec;

import java.util.Map;

/**
 * JSEF-Benchmark Phase5-D — 响应头注入安全版（CWE-113，难度 L2）
 *
 * 与 HeaderInjectionFromParam 对照：写入响应头前校验/剥离 CRLF 与控制字符，
 * 杜绝头注入，是真正的 SAFE，用于计算 TN / 误报（FP）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实投毒脚本。
 */
public class HeaderInjectionFromParamSafe {

    static void addHeader(Map<String, String> headers, String userValue) {
        // 拒绝含控制字符的值，仅允许可见字符
        if (userValue.matches("[\\x20-\\x7e]*")) {
            // [CHECKPOINT id=JSEF-CX-002S cwe=113 level=L2 source=request parameter sink=response.setHeader expect=SAFE]
            headers.put("X-Custom", userValue); // 已校验，无头注入
        } else {
            throw new IllegalArgumentException("invalid header value");
        }
    }
}
