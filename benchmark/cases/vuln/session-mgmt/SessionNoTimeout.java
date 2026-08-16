package com.jsef.benchmark.vuln;

import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-613 会话过期不足：创建会话后未设置最大非活动间隔，
 * 会话将保持有效直到浏览器关闭，攻击者可长期复用被盗会话。
 *
 * 修复：调用 session.setMaxInactiveInterval(shortSeconds) 限定生命周期。
 */
@RestController
public class SessionNoTimeout {

    @PostMapping("/api/v1/session/unsafe/notimeout")
    public String login(@RequestParam String user, HttpSession session) {
        session.setAttribute("user", user);
        // [CHECKPOINT id=JSEF-COMP-001 cwe=613 level=L1 source=user param sink=session (no setMaxInactiveInterval) expect=VULN]
        session.setMaxInactiveInterval(-1); // -1 = 永不过期
        return "logged in";
    }
}
