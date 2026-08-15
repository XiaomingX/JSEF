/*
 * JSEF Benchmark 安全样本 — 跳过支付步骤（逻辑漏洞/业务流程，步骤顺序绕过，CWE-862 缺失授权，L4）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：orderId 来自请求，但激活需校验支付状态。
 *   ② 激活前校验 paid==true，杜绝跳单。
 * 可达性说明：activate 先校验 paid==true，否则拒绝，保证未支付订单不可激活。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实跳单利用脚本，不生成针对真实目标工具。
 * 修复要点（对照 vuln）：激活前校验 paid==true。
 */
package com.jsef.benchmark.sec.logic;

public class SkipPaymentStep_Safe {

    /**
     * 安全入口：激活前校验支付状态。
     */
    public boolean activate(String orderId) {
        boolean paid = loadPaid(orderId);
        if (!paid) {                              // 步骤顺序校验：支付未完成拒绝
            return false;
        }
        // [CHECKPOINT id=JSEF-WF-002S cwe=862 level=L4 source=orderId sink=doActivate after paid==true check expect=SAFE]
        doActivate(orderId);                       // 仅已支付可激活
        return true;
    }

    static boolean loadPaid(String orderId) { return true; }
    static void doActivate(String orderId) { /* 演示：发货/激活，无副作用 */ }
}
