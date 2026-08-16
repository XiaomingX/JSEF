package com.jsef.benchmark.sec;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-613 修复：认证成功后调用 changeSessionId 使旧会话标识失效。
 */
@RestController
public class SessionFixationSafe {

    @PostMapping("/api/v1/session/safe/fixation")
    public String login(@RequestParam String user, HttpServletRequest request) {
        HttpSession session = request.getSession();
        // [CHECKPOINT id=JSEF-COMP-002S cwe=613 level=L1 source=user param sink=request.changeSessionId() expect=SAFE]
        request.changeSessionId(); // 登录后复活会话标识
        session.setAttribute("authenticatedUser", user);
        return "authenticated (new session id)";
    }
}
