/*
 * JSEF Benchmark 安全样本 — 不安全 Cookie（A05，CWE-614，L2）
 * SAFE 版：会话 Cookie 设置 HttpOnly 与 Secure 标志。
 * 测试点：强 SAST/LLM 应识别标志齐全而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
public class InsecureCookieSafe {

    /**
     * 安全入口：Cookie 加 HttpOnly/Secure。
     */
    static String buildSessionCookie(String sid) {
        // [CHECKPOINT id=JSEF-A05-005S cwe=614 level=L2 source=session id sink=Set-Cookie (HttpOnly; Secure) expect=SAFE]
        return "JSESSIONID=" + sid + "; HttpOnly; Secure; SameSite=Strict";
    }
}
