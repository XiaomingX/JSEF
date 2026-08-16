package com.jsef.benchmark.sec;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-640 修复：使用密码学安全随机令牌并限定短期有效期。
 */
@RestController
public class PredictableResetTokenSafe {

    private static final long TTL_SECONDS = 900; // 15 分钟

    @PostMapping("/api/v1/password/safe/reset")
    public String reset(@RequestParam String username) {
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        long expiresAt = Instant.now().getEpochSecond() + TTL_SECONDS;
        // [CHECKPOINT id=JSEF-COMP-004S cwe=640 level=L2 source=username param sink=SecureRandom token (TTL) expect=SAFE]
        return "reset link: /reset?token=" + token + "&exp=" + expiresAt;
    }
}
