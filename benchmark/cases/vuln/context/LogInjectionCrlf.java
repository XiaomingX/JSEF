package com.jsef.benchmark.vuln;

/**
 * JSEF-Benchmark Phase5-D — 日志注入 CRLF（CWE-93，难度 L2）
 *
 * 混淆点（为什么容易被误判）：
 * sink 是"写日志"（log.info），不是经典的 SQL/RCE 终点，很多注入规则不覆盖它。
 * 但用户输入含 "\n" 或 "\r" 时，攻击者可插入伪造的日志行（伪造审计记录、
 * 掩盖真实行为），属于日志注入 VULN（CWE-93）。弱被测对象易漏报（FN）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实伪造日志脚本。
 */
public class LogInjectionCrlf {

    /**
     * 危险入口：用户可控消息直接写日志，未过滤换行符。
     */
    static void log(String userMsg) {
        // [CHECKPOINT id=JSEF-CX-001 cwe=93 level=L2 source=user-controlled message sink=logger.info (log line) expect=VULN]
        System.out.println("[AUDIT] " + userMsg); // 含 \r\n 可拆分伪造日志行
    }
}
