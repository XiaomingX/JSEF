/*
 * JSEF Benchmark 样本 — 来源/签名/完整性校验缺失：webhook HMAC 验签（safe 对照，CWE-345，L3）
 * 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

public class WebhookNoSigVerifySafe {

    static final String SECRET = System.getenv("WEBHOOK_SECRET");

    // 安全：先用共享密钥校验 HMAC 签名，失败拒绝
    static void handle(String signatureHeader, String payload) {
        // [CHECKPOINT id=JSEF-V1-ORG-001S cwe=345 level=L3 source=webhook payload + X-Signature header sink=process(payload) (HMAC verified) expect=SAFE]
        if (!hmacEqual(signatureHeader, payload)) {
            throw new SecurityException("invalid webhook signature");
        }
        process(payload);
    }

    static boolean hmacEqual(String sig, String payload) {
        return sig != null && sig.equals("mock-hmac(" + payload + ")");
    }

    static void process(String p) { /* 业务动作 */ }
}
