/*
 * JSEF Benchmark 样本 — 不安全 Cookie（A05，CWE-614，L2）
 * 运行态需 JSEF 依赖（Servlet API）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实会话劫持利用。
 *
 * 知识点（A05 安全配置错误，CWE-614 敏感 Cookie 无 Secure 标志）：
 *   会话 Cookie 未设置 HttpOnly / Secure，可被 JS 读取（XSS 盗取）或经明文 HTTP 传输。
 */
public class InsecureCookie {

    /**
     * 危险入口：Cookie 缺 HttpOnly/Secure。
     */
    static String buildSessionCookie(String sid) {
        // [CHECKPOINT id=JSEF-A05-005 cwe=614 level=L2 source=session id sink=Set-Cookie (no HttpOnly/Secure) expect=VULN]
        return "JSESSIONID=" + sid;   // 缺 HttpOnly/Secure → 可被窃取
    }
}
