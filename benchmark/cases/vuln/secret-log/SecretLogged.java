/*
 * JSEF Benchmark 样本 — 敏感 Secret 经日志写入外泄（CWE-532，L2）
 * 场景：业务逻辑从配置/请求中取出 API Secret，将其连同上下文构造为
 * 日志字符串直接交给 logger，导致生产日志中明文留存密钥。
 *
 * 设计意图：补充「敏感信息外泄」的新 sink 语义——现有样本覆盖
 * 响应体明文（SENSITIVE-001/002）与日志缺上下文（A09-002），
 * 但缺「secret 对象被 logger.info 写入日志」这一污点流。
 *
 * 借鉴 Terminal-Bench 2.1 的 vulnerable-secret（密钥意外外泄）。
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
package com.jsef.benchmark.vuln;

import java.util.logging.Logger;

public class SecretLogged {

    private static final Logger log = Logger.getLogger(SecretLogged.class.getName());

    // [VULN] 敏感密钥经字符串拼接进入日志 sink
    static void processApiCall(String apiKey, String action) {
        // source：不可信/敏感 apiKey（来自请求头或配置）
        // sink：logger.info —— 密钥明文写入日志
        // [CHECKPOINT id=JSEF-SECLOG-001 cwe=532 level=L2 source=apiKey sink=logger.info (secret written to log) expect=VULN]
        log.info("Handling action=" + action + " with apiKey=" + apiKey);
    }
}
