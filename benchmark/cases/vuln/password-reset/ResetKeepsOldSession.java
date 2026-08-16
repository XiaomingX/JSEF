package com.jsef.benchmark.vuln;

import java.util.HashSet;
import java.util.Set;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-640 密码重置后未使旧会话失效：重置口令成功但已登录的活跃会话
 * 仍有效，攻击者若已持有旧会话可继续冒用账户。
 *
 * 修复：重置成功后调用 SessionRegistry 使该用户所有活跃会话失效。
 */
@RestController
public class ResetKeepsOldSession {

    private final Set<String> activeSessions = new HashSet<>();

    @PostMapping("/api/v1/password/unsafe/doReset")
    public String doReset(@RequestParam String username, @RequestParam String newPassword) {
        // 假设已更新口令
        // [CHECKPOINT id=JSEF-COMP-005 cwe=640 level=L2 source=username param sink=activeSessions (not invalidated) expect=VULN]
        return "password updated; old sessions still valid"; // 未使旧会话失效
    }
}
