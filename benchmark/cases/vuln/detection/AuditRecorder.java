package com.jsef.benchmark.vuln.detection;

import java.time.Instant;

/**
 * JSEF-Benchmark 样本族 A：检测压力 — 审计记录器（辅助类）
 *
 * 语义：真实系统中每条 SQL 执行前都会经过此审计记录器，把 SQL 文本 + 调用方
 * 写入审计日志（WORM / 追加日志）。它是"检测压力"语义的载体——危险 sink 前
 * 存在一条会把危险操作记录下来的监控链路。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class AuditRecorder {

    private static final StringBuilder AUDIT = new StringBuilder();

    /**
     * 语义等价：把 SQL 与调用方写入追加式审计日志（不可被业务代码删除）。
     *
     * @param sql        待执行的 SQL 文本（含不可信部分）
     * @param callerName 调用方标识
     * @return 记录后的审计行（仅用于演示，真实系统写入日志存储）
     */
    public String audit(String sql, String callerName) {
        String line = Instant.now() + " | caller=" + callerName + " | sql=" + sql;
        AUDIT.append(line).append('\n');
        System.out.println("[audit] " + line);
        return line;
    }

    /** 仅用于演示：读取累计的审计内容。 */
    public static String dump() {
        return AUDIT.toString();
    }
}
