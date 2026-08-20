package com.jsef.benchmark.vuln;

import java.time.Instant;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-640 口令重置 TOCTOU（L3 高区分度）。
 *
 * 【难点/区分点】区别于 L2 单方法 `PredictableResetToken`，本样本把"可预测性"
 * 与"时序（TOCTOU）"两个难点叠加，跨方法：
 *   1. 可预测 token：由 `username + 当前时间戳秒` 拼接，攻击者已知用户名并
 *      可估算时间戳，即可伪造重置 token，无需任何随机性。
 *   2. 时效校验时序错误（TOCTOU）：token 的过期校验被推迟到"重置处理之后"
 *      才做，即先信任并消费 token（据此完成重置），最后才发现 token 已过期。
 *      正确的顺序是"生成时记录过期时刻、使用前先校验时效、再执行重置"。
 *   3. 跨方法：token 生成在 `issue`，消费/重置在 `redeem`，过期判断散落在
 *      两个方法间，评测需追踪时序而非只看单点拼接。
 *
 * 修复：SecureRandom 生成 + 单次使用 + 使用前强时效校验（见 sec 对照）。
 */
@RestController
public class ResetTokenToctouVuln {

    // 语义桩：替代真实口令重置服务，声明重置语义，不产生真实攻击载荷。
    // 语义等价: POST /reset —— 依据 token 重置指定账户口令。
    private String resetPassword(String token, String user) {
        return "[reset] account=" + user + " token=" + token;
    }

    // 语义桩：判断 token 是否过期（真实场景会查缓存中的 issuedAt）。
    // 语义等价: redis.get(TTL(token)) == null  -> 已过期
    private boolean isTokenExpired(String token) {
        // 简化：token 尾部的时间戳超过 10 分钟视为过期。
        String[] parts = token.split(":");
        if (parts.length < 2) return true;
        long issued = Long.parseLong(parts[1]);
        return (Instant.now().getEpochSecond() - issued) > 600L;
    }

    /**
     * 签发可预测 token：username + 当前时间戳秒。
     */
    @PostMapping("/api/v1/password/unsafe/reset-issue")
    public String issue(@RequestParam String username) {
        long ts = Instant.now().getEpochSecond();
        String token = username + ":" + ts; // 可预测：用户名 + 时间戳秒
        return "reset link: /reset?token=" + token;
    }

    /**
     * 兑换/重置：先用可预测 token 完成重置，之后才补做过期校验（TOCTOU）。
     * checkpoint 位于"可预测 token 进入重置处理"的精确行。
     */
    @PostMapping("/api/v1/password/unsafe/reset-redeem")
    public String redeem(@RequestParam String token) {
        String user = token.split(":")[0]; // 从 token 反解账户
        // [CHECKPOINT id=JSEF-RESET-001 cwe=640 level=L3 source=username param sink=resetPassword (predictable token, expiry checked after use) expect=VULN trace=benchmark/cases/vuln/password-reset/ResetTokenToctouVuln.java:48]
        String result = resetPassword(token, user); // 先信任并消费 token
        if (isTokenExpired(token)) { // 事后才发现过期，为时已晚
            return "rejected (expired after use) — but reset already processed: " + result;
        }
        return "reset processed: " + result;
    }
}
