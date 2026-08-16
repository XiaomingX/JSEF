package com.jsef.benchmark.vuln;

import java.time.Instant;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-640 密码重置令牌可预测：令牌仅由用户名与时间戳拼接而成，
 * 攻击者已知用户名并可估算时间戳即可伪造重置链接，劫持任意账户。
 *
 * 修复：使用密码学安全随机令牌（如 SecureRandom 生成 32 字节）并设定短期过期。
 */
@RestController
public class PredictableResetToken {

    @PostMapping("/api/v1/password/unsafe/reset")
    public String reset(@RequestParam String username) {
        long ts = Instant.now().getEpochSecond();
        String token = username + ":" + ts; // 可预测
        // [CHECKPOINT id=JSEF-COMP-004 cwe=640 level=L2 source=username param sink=reset token (predictable) expect=VULN]
        return "reset link: /reset?token=" + token;
    }
}
