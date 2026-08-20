package com.jsef.benchmark.vuln;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-613 跨方法会话固定（L3 高区分度）。
 *
 * 【难点/区分点】区别于 L1 单方法 `SessionFixation`：
 *   1. 跨方法状态：会话固定逻辑被拆到两个独立的 @PostMapping handler 方法——
 *      `login` 负责写入身份，`access` 负责读取会话做鉴权。评测模型需要跨
 *      方法（跨 handler）追踪"旧 session 未轮换"这一状态，不能只看单点。
 *   2. 时序/顺序语义：校验发生在 `access`（登录之后），但身份是用登录前的
 *      旧 sessionId 写入的，且 login 之后从未调用 `changeSessionId()`。
 *      攻击者先植入已知 JSESSIONID，受害者 login 后旧 id 依然有效，攻击者可
 *      用该 id 冒用受害者身份进入 access。
 *   3. 状态必须"跨两次 HTTP 请求"保持——session 对象在两方法间共享，评测需
 *      识别 access 中的身份校验复用了未轮换的旧会话。
 *
 * 修复：login 认证成功后调用 request.changeSessionId()；access 校验强制走新会话。
 */
@RestController
public class CrossMethodSessionFixation {

    // 两 handler 共享的会话状态：登录方法在此写入身份，access 方法在此校验。
    private String authenticatedUser = null;
    private String currentSessionId = null;

    /**
     * 登录：把用户身份写入会话，但不换 sessionId。
     * trace 目标行——会话固定根因在此：写入身份后未 changeSessionId。
     */
    @PostMapping("/api/v1/session/unsafe/crossfixation-login")
    public String login(@RequestParam String user, HttpServletRequest request) {
        HttpSession session = request.getSession(); // 复用登录前旧 JSESSIONID
        this.authenticatedUser = user;
        this.currentSessionId = session.getId();
        // 关键缺陷：这里应当 request.changeSessionId()，但未调用，
        // 旧会话标识继续有效，供 access 方法复用。
        return "logged-in session=" + this.currentSessionId;
    }

    /**
     * 访问受保护资源：用旧 sessionId 校验身份。
     * checkpoint 位于"access 用旧 session 校验身份"的精确行。
     */
    @PostMapping("/api/v1/session/unsafe/crossfixation-access")
    public String access(HttpServletRequest request) {
        HttpSession session = request.getSession();
        String currentId = session.getId();
        // [CHECKPOINT id=JSEF-SESS-001 cwe=613 level=L3 source=user param sink=session auth (old sessionId not rotated) expect=VULN trace=benchmark/cases/vuln/session-mgmt/CrossMethodSessionFixation.java:39]
        if (this.authenticatedUser != null && currentId.equals(this.currentSessionId)) {
            return "access granted for " + this.authenticatedUser + " via session " + currentId;
        }
        return "access denied";
    }
}
