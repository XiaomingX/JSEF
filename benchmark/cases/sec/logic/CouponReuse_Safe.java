/*
 * JSEF Benchmark 安全样本 — 优惠券重复核销（逻辑漏洞/支付，CWE-840，L3）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：couponCode 来自请求，但服务端需保证一次性消费。
 *   ② 核销必须是原子的 check-then-act：先检查、后添加的两步非原子组合在并发下会重复核销。
 *
 * 修复要点（对照 vuln）：
 *   - 原 HashSet.contains() + add() 是两步非原子操作，并发下多线程可同时通过 contains 检查
 *     → 改用 ConcurrentHashMap.newKeySet()，利用 add() 的原子语义（返回 false 表示已存在）。
 *   - 单次 add() 原子性保证：只有第一个调用方能拿到 true，其余并发调用均返回 false 被拒绝。
 *
 * 可达性说明：add() 成功后才调用 applyDiscount，保证全局一次性消费。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实薅券利用脚本，不生成针对真实目标工具。
 */
package com.jsef.benchmark.sec.logic;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class CouponReuse_Safe {

    // ConcurrentHashMap.newKeySet()：线程安全集合，add() 本身为原子操作
    static final Set<String> USED = ConcurrentHashMap.newKeySet();

    /**
     * 安全入口：原子 add() 代替 contains()+add() 两步，消除并发重复核销 TOCTOU。
     */
    public boolean redeem(String couponCode) {
        // [CHECKPOINT id=JSEF-PAY-002S cwe=840 level=L3 source=couponCode sink=applyDiscount(code) after atomic dedupe check expect=SAFE]
        if (!USED.add(couponCode)) {  // 原子：已存在则返回 false，并发安全
            return false;             // 已核销，拒绝
        }
        applyDiscount(couponCode);    // 仅首次成功核销方可执行
        return true;
    }

    static void applyDiscount(String code) { /* 演示：应用折扣，无副作用 */ }
}
