/*
 * JSEF Benchmark 样本 — 信任边界安全对照 (CWE-501, L3)
 * 存入会话前校验，读取时再次校验。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import java.util.regex.Pattern;

public class TrustBoundaryViolationSafe {

    interface Session { void setAttribute(String k, Object v); Object getAttribute(String k); }

    private static final Pattern SAFE = Pattern.compile("^[a-zA-Z0-9_\\-]+$");

    static void store(Session session, String userInput) {
        if (!SAFE.matcher(userInput).matches()) {
            throw new IllegalArgumentException("invalid input");
        }
        // [CHECKPOINT id=JSEF-EXT-009S cwe=501 level=L3 source=userInput sink=validate before session.setAttribute expect=SAFE]
        session.setAttribute("trustedData", userInput);
    }

    static String consume(Session session) {
        String data = (String) session.getAttribute("trustedData");
        if (!SAFE.matcher(data).matches()) {
            throw new IllegalArgumentException("invalid trusted data");
        }
        return "forward:" + data;
    }
}
