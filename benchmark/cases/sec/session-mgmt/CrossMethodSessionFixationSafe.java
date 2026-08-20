package com.jsef.benchmark.sec;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-613 跨方法会话固定安全对照（L3）。
 *
 * 【难点/区分点】与 vuln 同构的跨方法结构，但修复点正确：
 *   1. login 认证成功后调用 request.changeSessionId() 轮换会话标识，旧
 *      JSESSIONID 立即失效，攻击者预先植入的 id 无法再被复用。
 *   2. access 方法强制校验"当前会话 id 必须等于登录后记录的新会话 id"，
 *      若外部仍用旧 id 请求，身份校验不通过（新 id 已不同）。
 *   3. 时序正确：轮换发生在写入身份之前/之时，校验发生在轮换之后——
 *      符合"先轮换、后鉴权"的安全顺序，而非 TOCTOU 式"先信任后校验"。
 *
 * 评分：SAFE 侧信任实现——changeSessionId 是真实防护，校验强制走新会话。
 */
@RestController
public class CrossMethodSessionFixationSafe {

    private String authenticatedUser = null;
    private String rotatedSessionId = null;

    /**
     * 登录：认证成功后轮换会话标识，再写入身份。
     */
    @PostMapping("/api/v1/session/safe/crossfixation-login")
    public String login(@RequestParam String user, HttpServletRequest request) {
        HttpSession session = request.getSession();
        request.changeSessionId(); // 轮换：旧 JSESSIONID 立即失效
        this.authenticatedUser = user;
        this.rotatedSessionId = session.getId(); // 记录轮换后的新 id
        return "logged-in new-session=" + this.rotatedSessionId;
    }

    /**
     * 访问受保护资源：强制校验当前会话 id 是轮换后的新 id。
     * checkpoint 位于"access 强制走新会话校验"的精确行。
     */
    @PostMapping("/api/v1/session/safe/crossfixation-access")
    public String access(HttpServletRequest request) {
        HttpSession session = request.getSession();
        String currentId = session.getId();
        // [CHECKPOINT id=JSEF-SESS-001S cwe=613 level=L3 source=user param sink=session auth (enforce rotated new sessionId) expect=SAFE trace=benchmark/cases/sec/session-mgmt/CrossMethodSessionFixationSafe.java:34]
        if (this.authenticatedUser != null
                && currentId.equals(this.rotatedSessionId)
                && !this.rotatedSessionId.isEmpty()) {
            return "access granted for " + this.authenticatedUser + " via rotated session " + currentId;
        }
        return "access denied";
    }
}
