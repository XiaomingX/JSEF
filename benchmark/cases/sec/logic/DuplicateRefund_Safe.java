/*
 * JSEF Benchmark 安全样本 — 重复退款（逻辑漏洞/业务流程，状态机绕过，CWE-840，L4）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：orderId 来自请求，但退款需校验状态机。
 *   ② 退款前校验 status==PAID 且仅一次，杜绝重复退款。
 * 可达性说明：refund 先校验 status==PAID，否则拒绝，保证已退款/已关闭订单不可再次退款。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实重复退款利用脚本，不生成针对真实目标工具。
 * 修复要点（对照 vuln）：退款前校验 status==PAID 且仅一次。
 */
package com.jsef.benchmark.sec.logic;

public class DuplicateRefund_Safe {

    enum Status { PAID, REFUNDED, CLOSED }

    /**
     * 安全入口：退款前校验状态机。
     */
    public boolean refund(String orderId) {
        Status status = loadStatus(orderId);
        if (status != Status.PAID) {              // 状态机校验：仅 PAID 可退
            return false;
        }
        // [CHECKPOINT id=JSEF-WF-001S cwe=840 level=L4 source=orderId sink=doRefund after status==PAID check expect=SAFE]
        doRefund(orderId);                         // 仅一次退款
        return true;
    }

    static Status loadStatus(String orderId) { return Status.PAID; }
    static void doRefund(String orderId) { /* 演示：执行退款，无副作用 */ }
}
