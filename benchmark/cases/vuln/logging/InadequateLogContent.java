package com.jsef.benchmark.vuln.logging;

/**
 * JSEF Benchmark — A09 安全日志与监控失败（CWE-532，L2）
 *
 * 场景：日志记录缺少关键上下文（如用户名、来源 IP、动作），导致告警
 * 无法关联实体、难以定位攻击。
 *
 * 为何危险：无上下文的日志无法支撑检测与溯源，等于"有日志但不可用"，
 * 是 A09 中典型的信息不足/日志不完整问题。
 *
 * 安全底线：仅 localhost 演示语义。
 */
public class InadequateLogContent {

    /**
     * VULN：仅记录动作，缺少用户/IP 等上下文。
     */
    public static void onAction(String user, String clientIp, String action) {
        // source：安全相关动作事件
        // [CHECKPOINT id=JSEF-A09-002 cwe=532 level=L2 source=security action event sink=log (no user/ip context) expect=VULN]
        System.out.println("[INFO] action performed: " + action);   // 缺 user/ip
    }
}
