package com.jsef.benchmark.sec;

import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-613 修复：登录后设置合理的会话超时（如 30 分钟）。
 */
@RestController
public class SessionNoTimeoutSafe {

    @PostMapping("/api/v1/session/safe/notimeout")
    public String login(@RequestParam String user, HttpSession session) {
        session.setAttribute("user", user);
        // [CHECKPOINT id=JSEF-COMP-001S cwe=613 level=L1 source=user param sink=session.setMaxInactiveInterval(1800) expect=SAFE]
        session.setMaxInactiveInterval(1800); // 30 分钟超时
        return "logged in";
    }
}
