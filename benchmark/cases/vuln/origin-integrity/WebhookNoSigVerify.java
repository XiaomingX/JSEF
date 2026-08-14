/*
 * JSEF Benchmark 样本 — 来源/签名/完整性校验缺失：webhook 回调未验签（VulnGym 子类 BL-ORIGIN-INTEGRITY，CWE-345，L3）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"完整性语义"——webhook 回调直接信任请求体执行业务动作，未用共享密钥校验签名头。
 * 数据流干净，但缺失来源/完整性校验。静态分析需在 handle(payload) 处识别"未校验 X-Signature 头"。
 */
package com.jsef.benchmark.vuln;

public class WebhookNoSigVerify {

    // 危险：webhook 直接处理请求体，未校验签名头
    static void handle(String signatureHeader, String payload) {
        // source：不可信 HTTP body + X-Signature 头（攻击者可控）
        // [CHECKPOINT id=JSEF-V1-ORG-001 cwe=345 level=L3 source=webhook payload + X-Signature header sink=process(payload) (no HMAC verify) expect=VULN]
        process(payload);   // 越权：伪造 webhook 即可触发业务逻辑
    }

    static void process(String p) { /* 业务动作 */ }
}
