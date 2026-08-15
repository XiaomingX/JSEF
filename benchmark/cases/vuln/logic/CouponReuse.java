/*
 * JSEF Benchmark 样本 — 优惠券重复核销（逻辑漏洞/支付，CWE-840，L3）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：couponCode 来自 @RequestParam，服务端无一次性消费标记/去重。
 *   ② 同一 couponCode 可重复提交核销，攻击者无限次享受折扣。
 * 可达性说明：redeem 直接按 couponCode 查券并标记已用，但未记录/查询"已用集合"，
 *   污点（客户端券码）直达核销 sink 且无去重校验。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实薅券利用脚本，不生成针对真实目标工具。
 * 修复要点（对照 sec）：核销前查已用集合/状态，确保一次性消费。
 */
package com.jsef.benchmark.vuln.logic;

import java.util.HashSet;
import java.util.Set;

public class CouponReuse {

    static final Set<String> USED = new HashSet<>();   // 真实系统应持久化；此处仅示意

    /**
     * 危险入口：couponCode 直接取 @RequestParam，无去重。
     */
    public boolean redeem(@RequestParamLike String couponCode) {
        // 券码读取行：客户端可控 couponCode 进入作用域（source 抵达）
        String code = couponCode;                // 行26：参数读取（source 抵达）

        // [CHECKPOINT id=JSEF-PAY-002 cwe=840 level=L3 source=@RequestParam couponCode sink=applyDiscount(code) (no dedupe) expect=VULN trace=benchmark/cases/vuln/logic/CouponReuse.java:26,benchmark/cases/vuln/logic/CouponReuse.java:30]
        // 未去重核销行：直接核销，未检查 code 是否已存在于 USED
        applyDiscount(code);                      // 行30：缺陷点（无一次性消费/去重）
        USED.add(code);
        return true;
    }

    static void applyDiscount(String code) { /* 演示：应用折扣，无副作用 */ }

    @interface RequestParamLike {}
}
