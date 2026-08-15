/*
 * JSEF Benchmark 样本 — 重复退款（逻辑漏洞/业务流程，状态机绕过，CWE-840，L4）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：orderId 来自 @RequestParam，服务端未校验订单状态机。
 *   ② 已退款订单可再次退款，攻击者重复发起退款套现。
 * 可达性说明：refund 读取订单状态后未校验其是否为 PAID 即执行退款，状态机缺陷使已退款订单可再次退款。
 *   跨状态读取→未校验→执行三步，污点（客户端 orderId）直达退款 sink。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实重复退款利用脚本，不生成针对真实目标工具。
 * 修复要点（对照 sec）：退款前校验 status==PAID 且仅一次。
 */
package com.jsef.benchmark.vuln.logic;

public class DuplicateRefund {

    enum Status { PAID, REFUNDED, CLOSED }

    /**
     * 危险入口：orderId 直接取 @RequestParam，未校验状态机。
     */
    public boolean refund(@RequestParamLike String orderId) {
        // 订单状态读取行：按客户端 orderId 读取订单状态
        Status status = loadStatus(orderId);      // 行23：状态读取（source 抵达）

        // [CHECKPOINT id=JSEF-WF-001 cwe=840 level=L4 source=@RequestParam orderId sink=doRefund(orderId) (no status==PAID check) expect=VULN trace=benchmark/cases/vuln/logic/DuplicateRefund.java:23,benchmark/cases/vuln/logic/DuplicateRefund.java:27,benchmark/cases/vuln/logic/DuplicateRefund.java:29]
        // 未校验状态直接退款行：未判断 status==PAID，已退款订单可再次进入退款
        if (true) {                               // 行27：缺陷点（状态机未校验）
            // 退款执行行
            doRefund(orderId);                     // 行29：退款执行（可重复）
        }
        return true;
    }

    static Status loadStatus(String orderId) { return Status.REFUNDED; }  // 演示：返回已退款
    static void doRefund(String orderId) { /* 演示：执行退款，无副作用 */ }

    @interface RequestParamLike {}
}
