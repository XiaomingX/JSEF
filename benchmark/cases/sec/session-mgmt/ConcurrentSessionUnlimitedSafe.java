package com.jsef.benchmark.sec;

import java.util.concurrent.ConcurrentHashMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-613 修复：限制单用户最大并发会话数，超出则使最旧会话失效。
 */
@RestController
public class ConcurrentSessionUnlimitedSafe {

    private final ConcurrentHashMap<String, Integer> activeSessions = new ConcurrentHashMap<>();
    private static final int MAX_SESSIONS = 1;

    @PostMapping("/api/v1/session/safe/concurrent")
    public String login(@RequestParam String user) {
        int count = activeSessions.merge(user, 1, Integer::sum);
        // [CHECKPOINT id=JSEF-COMP-003S cwe=613 level=L2 source=user param sink=activeSessions (MAX_SESSIONS enforced) expect=SAFE]
        if (count > MAX_SESSIONS) {
            activeSessions.put(user, MAX_SESSIONS); // 超出使旧会话失效
            return "oldest session invalidated";
        }
        return "active sessions: " + count;
    }
}
