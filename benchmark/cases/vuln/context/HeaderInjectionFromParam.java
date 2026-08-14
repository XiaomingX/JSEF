package com.jsef.benchmark.vuln;

import java.util.Map;

/**
 * JSEF-Benchmark Phase5-D — 响应头注入（CWE-113，难度 L2）
 *
 * 混淆点（为什么容易被误判）：
 * sink 是设置 HTTP 响应头（response.setHeader），不是命令执行或 SQL。
 * 若用户输入含 "\r\n" 即可注入额外响应头（如 Set-Cookie / 任意头），
 * 衍生会话固定、缓存投毒、XSS 等。多数注入规则未覆盖响应头 sink，易漏报（FN）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实投毒脚本。
 */
public class HeaderInjectionFromParam {

    /**
     * 危险入口：用户参数直接拼入响应头值，未校验换行。
     */
    static void addHeader(Map<String, String> headers, String userValue) {
        // [CHECKPOINT id=JSEF-CX-002 cwe=113 level=L2 source=request parameter sink=response.setHeader expect=VULN]
        headers.put("X-Custom", userValue); // 含 \r\n 可注入额外响应头
    }
}
