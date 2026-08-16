/*
 * JSEF Benchmark 样本 — Cookie 安全标志安全对照 (CWE-614, L1)
 * 设置 secure 与 httpOnly 标志。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

public class InsecureCookieSafe {

    interface Cookie { void setValue(String v); void setSecure(boolean b); void setHttpOnly(boolean b); }

    static Cookie makeSessionCookie(String value) {
        Cookie c = new Cookie() {
            public void setValue(String v) {}
            public void setSecure(boolean b) {}
            public void setHttpOnly(boolean b) {}
        };
        c.setValue(value);
        c.setSecure(true);
        c.setHttpOnly(true);
        // [CHECKPOINT id=JSEF-EXT-010S cwe=614 level=L1 source=value sink=Cookie with secure=true httpOnly=true expect=SAFE]
        return c;
    }
}
