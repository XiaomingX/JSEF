/*
 * JSEF Benchmark 安全样本 — 优惠券重复核销（逻辑漏洞/支付，CWE-840，L3）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：couponCode 来自请求，但服务端需保证一次性消费。
 *   ② 核销前查已用集合/状态，重复提交被拒。
 * 可达性说明：redeem 先检查 code 是否已在 USED（原子去重），已用则拒绝，避免重复核销。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实薅券利用脚本，不生成针对真实目标工具。
 * 修复要点（对照 vuln）：核销前查已用集合/状态，确保一次性消费。
 */
package com.jsef.benchmark.sec.logic;

import java.util.HashSet;
import java.util.Set;

public class CouponReuse_Safe {

    static final Set<String> USED = new HashSet<>();

    /**
     * 安全入口：核销前查已用集合，保证一次性消费。
     */
    public boolean redeem(String couponCode) {
        if (USED.contains(couponCode)) {         // 去重校验
            return false;                        // 已核销，拒绝
        }
        // [CHECKPOINT id=JSEF-PAY-002S cwe=840 level=L3 source=couponCode sink=applyDiscount(code) after dedupe check expect=SAFE]
        applyDiscount(couponCode);               // 仅首次核销
        USED.add(couponCode);
        return true;
    }

    static void applyDiscount(String code) { /* 演示：应用折扣，无副作用 */ }
}
