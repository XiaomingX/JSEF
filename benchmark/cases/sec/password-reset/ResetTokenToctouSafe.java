package com.jsef.benchmark.sec;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-640 口令重置 TOCTOU 安全对照（L3）。
 *
 * 【难点/区分点】与 vuln 同构的跨方法签发/兑换结构，但三处修复正确：
 *   1. 强随机 token：SecureRandom 生成 32 字节 URL-safe token，攻击者无法预测。
 *   2. 单次使用：token 兑换后立即从缓存移除（remove），重放无效。
 *   3. 使用前强时效校验（时序正确）：redeem 先查 issuedAt 判过期，过期则拒绝
 *      且不执行重置——避免 vuln 的"先消费后校验" TOCTOU。
 *
 * 评分：SAFE 侧信任实现——SecureRandom/单次使用/先校验后使用均为真实防护。
 */
@RestController
public class ResetTokenToctouSafe {

    private static final long TTL_SECONDS = 900; // 15 分钟

    // 语义桩：token -> issuedAt 的存储（真实场景为 Redis + TTL）。
    // 语义等价: redis.setex(token, TTL, issuedAt)
    private final Map<String, Long> issuedStore = new ConcurrentHashMap<>();

    // 语义桩：替代真实口令重置服务，声明重置语义。
    // 语义等价: POST /reset —— 依据 token 重置指定账户口令。
    private String resetPassword(String token, String user) {
        return "[reset] account=" + user + " token=" + token;
    }

    /**
     * 签发强随机 token，并记录 issuedAt 供后续时效校验。
     */
    @PostMapping("/api/v1/password/safe/reset-issue")
    public String issue(@RequestParam String username) {
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        issuedStore.put(token, Instant.now().getEpochSecond());
        return "reset link: /reset?token=" + token;
    }

    /**
     * 兑换/重置：先做时效校验 + 单次使用（remove），过期/重放一律拒绝，再执行重置。
     * checkpoint 位于"使用前强时效校验"的精确行。
     */
    @PostMapping("/api/v1/password/safe/reset-redeem")
    public String redeem(@RequestParam String token, @RequestParam String username) {
        Long issuedAt = issuedStore.remove(token); // 单次使用：取出即删除，重放无效
        // [CHECKPOINT id=JSEF-RESET-001S cwe=640 level=L3 source=username param sink=resetPassword (SecureRandom token, single-use, expiry checked before use) expect=SAFE trace=benchmark/cases/sec/password-reset/ResetTokenToctouSafe.java:46]
        if (issuedAt == null) {
            return "rejected: token unknown or already used";
        }
        long age = Instant.now().getEpochSecond() - issuedAt;
        if (age > TTL_SECONDS) { // 使用前强时效校验，过期则拒绝，不执行重置
            return "rejected: token expired";
        }
        return "reset processed: " + resetPassword(token, username);
    }
}
