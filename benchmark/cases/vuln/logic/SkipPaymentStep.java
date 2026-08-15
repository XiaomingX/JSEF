/*
 * JSEF Benchmark 样本 — 跳过支付步骤（逻辑漏洞/业务流程，步骤顺序绕过，CWE-862 缺失授权，L4）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：orderId/activate 请求来自 @RequestParam，服务端未校验支付状态。
 *   ② 未校验支付状态直接发货/激活，攻击者跳过付款即享服务。
 * 可达性说明：activate 读取支付状态后未校验 paid==true 即激活，步骤顺序缺陷使未支付订单可激活。
 *   跨支付状态读取→未校验→激活三步，污点（客户端 orderId）直达激活 sink。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实跳单利用脚本，不生成针对真实目标工具。
 * 修复要点（对照 sec）：激活前校验 paid==true。
 */
package com.jsef.benchmark.vuln.logic;

public class SkipPaymentStep {

    /**
     * 危险入口：orderId 直接取 @RequestParam，未校验支付状态。
     */
    public boolean activate(@RequestParamLike String orderId) {
        // 支付状态读取行：按客户端 orderId 读取支付状态
        boolean paid = loadPaid(orderId);         // 行21：支付状态读取（source 抵达）

        // [CHECKPOINT id=JSEF-WF-002 cwe=862 level=L4 source=@RequestParam orderId sink=doActivate(orderId) (no paid==true check) expect=VULN trace=benchmark/cases/vuln/logic/SkipPaymentStep.java:21,benchmark/cases/vuln/logic/SkipPaymentStep.java:25,benchmark/cases/vuln/logic/SkipPaymentStep.java:27]
        // 未校验直接激活行：未判断 paid==true，未支付订单可激活
        if (true) {                               // 行25：缺陷点（步骤顺序未校验）
            // 激活执行行
            doActivate(orderId);                   // 行27：激活执行（可跳单）
        }
        return true;
    }

    static boolean loadPaid(String orderId) { return false; }  // 演示：未支付
    static void doActivate(String orderId) { /* 演示：发货/激活，无副作用 */ }

    @interface RequestParamLike {}
}
