package com.jsef.benchmark.vuln;

/**
 * JSEF-Benchmark Phase5-C — 错误信息泄露（CWE-209，难度 L2）
 *
 * 混淆点（为什么容易被误判）：
 * 这里没有"经典的" XSS/SQL 注入 sink，只是把异常 e.getMessage() 原样返回给前端。
 * 弱被测对象（尤其只盯注入类 sink 的）容易把它当成"无害日志/调试输出"而漏报。
 * 实际上异常信息会泄露内部细节（SQL 片段、堆栈、表名、路径），属于信息泄露类 VULN。
 *
 * 说明：本样本 category 复用既有的 security-header-missing 行（信息泄露/安全响应类），
 * 在 CSV 中以该 slug 登记，便于与同类 SAFE 对照计算 FP/TN。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实探测脚本。
 */
public class ErrorBasedInfoLeak {

    /**
     * 危险入口：将内部异常信息直接返回给客户端。
     */
    static String handle(Exception e) {
        // [CHECKPOINT id=JSEF-BL-002 cwe=209 level=L2 source=exception.getMessage() sink=HTTP response body expect=VULN]
        return "error: " + e.getMessage(); // 泄露内部实现细节（SQL/路径/表名）
    }
}
