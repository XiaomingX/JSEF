package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L4 — OAuth 回调无 state 校验的 CSRF 绑定 (CWE-352)
 *
 * 难度：L4（跨节点 / 业务链）。攻击者预生成“绑定自己账号”的 OAuth flow，
 * 受害者点击后访问 callback，因无 state 校验，受害者账号被绑定到攻击者账户。
 *
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 * 修复要点（OAuthStateSafe.java）：校验 state 与会话绑定 nonce。
 */
public class OAuthStateVuln {

    static class Session {
        String currentUser() { return "victim"; }
    }

    static class OAuthProvider {
        boolean isValidCode(String code) { return true; }
        String accountOf(String code) { return "attacker@example.com"; }
    }

    // [CHECKPOINT id=JSEF-NV402 cwe=352 level=L4 source=oauth callback (no state) sink=bindAccount (no state CSRF) expect=VULN trace=benchmark/cases/vuln/oauth-csrf/OAuthStateVuln.java:24,benchmark/cases/vuln/oauth-csrf/OAuthStateVuln.java:28]
    public void callback(String code, Session session, OAuthProvider provider) {
        // 发起 flow 行：攻击者预生成绑定自己账号的授权码，无 state 关联会话
        if (provider.isValidCode(code)) {
            // 绑定行：将当前受害者会话绑定到攻击者账户 → CSRF 账号绑定
            bindAccount(session.currentUser(), provider.accountOf(code));
        }
    }

    // 抽象 sink：语义等价 将 userId 与第三方 account 建立关联
    static void bindAccount(String userId, String oauthAccount) {
        System.out.println("[bind-account] " + userId + " <-> " + oauthAccount);
    }
}
