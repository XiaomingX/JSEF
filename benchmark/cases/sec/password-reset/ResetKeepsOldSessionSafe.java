package com.jsef.benchmark.sec;

import java.util.HashSet;
import java.util.Set;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-640 修复：重置成功后立即使该用户所有活跃会话失效。
 */
@RestController
public class ResetKeepsOldSessionSafe {

    private final Set<String> activeSessions = new HashSet<>();

    @PostMapping("/api/v1/password/safe/doReset")
    public String doReset(@RequestParam String username, @RequestParam String newPassword) {
        // 假设已更新口令
        // [CHECKPOINT id=JSEF-COMP-005S cwe=640 level=L2 source=username param sink=activeSessions.invalidateAll(user) expect=SAFE]
        activeSessions.remove(username); // 使旧会话失效
        return "password updated; old sessions invalidated";
    }
}
