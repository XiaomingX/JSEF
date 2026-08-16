/*
 * JSEF Benchmark 样本 — Cookie 安全标志缺失 (CWE-614, L1)
 * 创建 Cookie 未设置 secure / httpOnly 标志。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

public class InsecureCookie {

    interface Cookie { void setValue(String v); void setSecure(boolean b); void setHttpOnly(boolean b); }

    // 危险：会话 Cookie 无 secure / httpOnly
    static Cookie makeSessionCookie(String value) {
        Cookie c = new Cookie() {
            public void setValue(String v) {}
            public void setSecure(boolean b) {}
            public void setHttpOnly(boolean b) {}
        };
        c.setValue(value);
        // [CHECKPOINT id=JSEF-EXT-010 cwe=614 level=L1 source=value sink=Cookie created without secure/httpOnly expect=VULN]
        return c; // 可被 XSS 读取 / 明文传输
    }
}
