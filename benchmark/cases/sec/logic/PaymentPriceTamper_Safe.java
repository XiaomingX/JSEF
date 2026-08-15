/*
 * JSEF Benchmark 安全样本 — 支付价格篡改（逻辑漏洞/支付，CWE-840，L3）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：前端仅传 productId 与 quantity，amount 不得由客户端提供。
 *   ② 服务端按权威单价重算总额并校验非负，客户端无法篡改。
 * 可达性说明：服务端忽略任何客户端 amount，从 PRICE_CATALOG 取权威单价，total = serverPrice * qty，
 *   且校验 total >= 0，污点不抵达金额计算 sink。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实支付绕过利用脚本，不生成针对真实目标工具。
 * 修复要点（对照 vuln）：服务端按权威单价 × 数量重算总额，并强制校验非负。
 */
package com.jsef.benchmark.sec.logic;

import java.util.Map;

public class PaymentPriceTamper_Safe {

    static final Map<String, Double> PRICE_CATALOG = Map.of("SKU-1", 100.0);

    /**
     * 安全入口：金额由服务端权威来源计算，客户端 amount 被忽略。
     */
    public double createOrder(String productId, int quantity) {
        double serverPrice = PRICE_CATALOG.getOrDefault(productId, 0.0);  // 服务端取价
        // [CHECKPOINT id=JSEF-PAY-001S cwe=840 level=L3 source=server price (authoritative) sink=serverPrice * quantity (total, validated) expect=SAFE]
        double total = serverPrice * quantity;   // 客户端价格不可信，已忽略；下方校验非负
        if (total < 0) {
            throw new IllegalArgumentException("total must be non-negative");
        }
        return total;
    }
}
