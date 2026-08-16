package com.jsef.benchmark.vuln;

import java.util.concurrent.ConcurrentHashMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-613 并发会话无限制：同一用户可从任意数量设备同时登录，
 * 无法检测凭据泄露，且登出无法使其他活跃会话失效。
 *
 * 修复：维护每用户活跃会话集合，超出阈值时使旧会话失效（如 Spring Security 的
 * maximumSessions + ConcurrentSessionControlAuthenticationStrategy）。
 */
@RestController
public class ConcurrentSessionUnlimited {

    private final ConcurrentHashMap<String, Integer> activeSessions = new ConcurrentHashMap<>();

    @PostMapping("/api/v1/session/unsafe/concurrent")
    public String login(@RequestParam String user) {
        int count = activeSessions.merge(user, 1, Integer::sum);
        // [CHECKPOINT id=JSEF-COMP-003 cwe=613 level=L2 source=user param sink=activeSessions (no limit) expect=VULN]
        return "active sessions: " + count; // 无上限，永不使旧会话失效
    }
}
