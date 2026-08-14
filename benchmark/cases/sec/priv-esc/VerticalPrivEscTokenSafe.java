/*
 * JSEF Benchmark 样本 — 权限提升精分：role 经服务端映射校验（safe 对照，CWE-285，L4）
 * 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

public class VerticalPrivEscTokenSafe {

    static final class Token { final String role; Token(String r){ this.role=r; } }

    // 安全：role 经服务端权威映射校验，token 声明仅作参考
    static boolean canAccessAdmin(Token token, String serverRole) {
        // [CHECKPOINT id=JSEF-V1-PRV-002S cwe=285 level=L4 source=token.role (ignored) sink=authorization (serverRole) expect=SAFE]
        return "admin".equals(serverRole);
    }
}
