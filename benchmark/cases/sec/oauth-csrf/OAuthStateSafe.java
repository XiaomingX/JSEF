package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L4 — OAuth 回调 state 校验修复 (CWE-352) expect=SAFE
 *
 * sec 侧：state 为会话绑定的一次性 nonce；回调时校验 state 匹配，
 * 不匹配直接拒绝，阻断攻击者预生成 flow 的 CSRF 绑定。
 *
 * 安全底线：按实现判定为安全。
 */
public class OAuthStateSafe {

    static class Session {
        String currentUser() { return "victim"; }
        String getExpectedState() { return "nonce-xyz-123"; }
    }

    static class OAuthProvider {
        boolean isValidCode(String code) { return true; }
        String accountOf(String code) { return "attacker@example.com"; }
    }

    // [CHECKPOINT id=JSEF-NV402S cwe=352 level=L4 source=oauth callback (with state) sink=bindAccount expect=SAFE trace=benchmark/cases/sec/oauth-csrf/OAuthStateSafe.java:24,benchmark/cases/sec/oauth-csrf/OAuthStateSafe.java:30]
    public void callback(String code, String state, Session session, OAuthProvider provider) {
        // 校验 state 是否与当前会话 nonce 匹配
        if (!session.getExpectedState().equals(state)) {
            throw new IllegalStateException("invalid oauth state");
        }
        if (provider.isValidCode(code)) {
            bindAccount(session.currentUser(), provider.accountOf(code));
        }
    }

    static void bindAccount(String userId, String oauthAccount) {
        System.out.println("[bind-account] " + userId + " <-> " + oauthAccount);
    }
}
