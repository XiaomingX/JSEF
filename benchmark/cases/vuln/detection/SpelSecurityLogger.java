package com.jsef.benchmark.vuln.detection;

import java.time.Instant;

/**
 * JSEF-Benchmark 样本族 A：检测压力 — SpEL 安全日志记录器（辅助类）
 *
 * 语义：真实系统中每次 SpEL 求值前会把表达式 + 栈回溯写入安全日志（SIEM / WORM
 * 追加日志），用于事后审计。它是"检测压力"语义的载体——危险求值前存在一条会把
 * 表达式与调用栈记录下来的监控链路。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class SpelSecurityLogger {

    private static final StringBuilder SEC_LOG = new StringBuilder();

    /**
     * 语义等价：把表达式文本与当前调用栈写入安全日志（不可被业务代码删除）。
     *
     * @param expression 待求值的 SpEL 表达式文本（含不可信部分）
     * @return 记录后的安全日志行
     */
    public String logExpression(String expression) {
        String stack = stackTrace();
        String line = Instant.now() + " | expr=" + expression + " | stack=" + stack;
        SEC_LOG.append(line).append('\n');
        System.out.println("[security-log] " + line);
        return line;
    }

    private String stackTrace() {
        StringBuilder sb = new StringBuilder();
        for (StackTraceElement el : Thread.currentThread().getStackTrace()) {
            sb.append(el.getClassName()).append('#').append(el.getMethodName()).append(';');
        }
        return sb.toString();
    }

    /** 仅用于演示：读取累计的安全日志内容。 */
    public static String dump() {
        return SEC_LOG.toString();
    }
}
