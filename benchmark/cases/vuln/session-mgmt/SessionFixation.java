package com.jsef.benchmark.vuln;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-613 会话固定：用户登录前后复用同一个 session，
 * 攻击者可在登录前植入已知 JSESSIONID，待受害者登录后冒用其身份。
 *
 * 修复：认证成功后调用 request.changeSessionId() 生成新会话标识。
 */
@RestController
public class SessionFixation {

    @PostMapping("/api/v1/session/unsafe/fixation")
    public String login(@RequestParam String user, HttpServletRequest request) {
        HttpSession session = request.getSession();
        session.setAttribute("authenticatedUser", user);
        // [CHECKPOINT id=JSEF-COMP-002 cwe=613 level=L1 source=user param sink=session (no changeSessionId) expect=VULN]
        return "authenticated (same session id)"; // 未调用 changeSessionId
    }
}
