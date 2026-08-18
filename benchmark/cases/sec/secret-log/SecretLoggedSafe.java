/*
 * JSEF Benchmark 样本 — 敏感 Secret 经日志写入外泄 安全对照（CWE-532，L2）
 * 安全做法：日志中只记录密钥的非敏感派生信息（如掩码/哈希前缀），
 * 绝不记录明文密钥。
 *
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import java.util.logging.Logger;

public class SecretLoggedSafe {

    private static final Logger log = Logger.getLogger(SecretLoggedSafe.class.getName());

    /** 掩码：只保留前缀用于排查，绝不泄露完整密钥。 */
    static String mask(String secret) {
        if (secret == null || secret.length() <= 4) return "***";
        return secret.substring(0, 4) + "***(masked)";
    }

    // [SAFE] 日志仅记录掩码后的密钥标识，明文不落日志
    static void processApiCall(String apiKey, String action) {
        // source：敏感 apiKey；sink：logger.info（已掩码，无明文泄露）
        // [CHECKPOINT id=JSEF-SECLOG-001S cwe=532 level=L2 source=apiKey sink=logger.info (masked) expect=SAFE]
        log.info("Handling action=" + action + " with apiKey=" + mask(apiKey));
    }
}
