/*
 * JSEF Benchmark 样本 — 权限提升精分：token 中 role 未校验（VulnGym 子类 BL-PRIV-ESC，CWE-285，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"角色来源语义"——授权决策直接读取 token 中可自行声明的 role，未与服务端映射校验。
 * 数据流干净，但角色判定依赖不可信声明。静态分析需在 authz(role) 处识别"role 取自 token 且未校验"。
 */
package com.jsef.benchmark.vuln;

public class VerticalPrivEscToken {

    // 演示用：token 与上下文
    static final class Token { final String role; Token(String r){ this.role=r; } }

    // 危险：授权决策直接用 token 里的 role
    static boolean canAccessAdmin(Token token) {
        // source：不可信 token.role（HTTP 参数，可伪造为 admin）
        // [CHECKPOINT id=JSEF-V1-PRV-002 cwe=285 level=L4 source=token.role (unverified claim) sink=authorization decision expect=VULN]
        return "admin".equals(token.role);   // 越权：伪造 role=admin 即放行
    }
}
