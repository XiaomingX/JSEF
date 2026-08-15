/*
 * JSEF Benchmark 样本 — 支付价格篡改（逻辑漏洞/支付，CWE-840，L3）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：订单 amount（金额）、quantity（数量）直接来自 @RequestParam，服务端未重算。
 *   ② 攻击者传负值或篡改数量即可绕过总额校验，达到低价/反向支付效果。
 * 可达性说明：OrderController.createOrder 直接信任前端提交的 amount 与 quantity 计算 total，
 *   服务端未持有权威单价，也未校验非负，污点（客户端参数）直达金额计算 sink 且无校验。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实支付绕过利用脚本，不生成针对真实目标工具。
 * 修复要点（对照 sec）：服务端按权威单价 × 数量重算总额，并校验 total >= 0。
 */
package com.jsef.benchmark.vuln.logic;

import java.util.Map;

public class PaymentPriceTamper {

    // 简化演示：商品权威单价（真实系统应来自 DB/计价服务）
    static final Map<String, Double> PRICE_CATALOG = Map.of("SKU-1", 100.0);

    /**
     * 危险入口：金额/数量直接取 @RequestParam，服务端未重算。
     */
    public double createOrder(String productId,
                              @RequestParamLike double amount,
                              @RequestParamLike int quantity) {
        // 参数读取行：客户端可控 amount / quantity 直接作为方法参数进入作用域
        double clientAmount = amount;            // 行29：参数读取（source 抵达）
        int clientQty = quantity;                // 行30：参数读取（source 抵达）

        // [CHECKPOINT id=JSEF-PAY-001 cwe=840 level=L3 source=@RequestParam amount/quantity sink=total = clientAmount * clientQty (no server recompute) expect=VULN trace=benchmark/cases/vuln/logic/PaymentPriceTamper.java:29,benchmark/cases/vuln/logic/PaymentPriceTamper.java:33]
        // 未校验直接使用行：total 直接由客户端参数算出，无服务端重算、无非负校验
        double total = clientAmount * clientQty;  // 行33：缺陷点（未重算、未校验非负）
        return total;
    }

    // 仅用于人工阅读的自包含演示注解（非运行时）
    @interface RequestParamLike {}
}
