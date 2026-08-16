package com.jsef.benchmark.vuln;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JSEF-Benchmark — 日志注入多行伪造（CWE-117，L2 多跳）
 *
 * 不可信搜索关键词经中间变量拼接后写入日志。攻击者注入 CRLF 可拆分出
 * 伪造的多行日志（如 "INFO root granted admin"），误导审计与告警关联分析。
 *
 * CodeQL 对应查询：java/log-injection。
 *
 * 安全底线：仅 localhost 教学演示。
 *
 * 修复要点（对照 LogInjectionMultilineSafe.java）：结构化/字段化记录，
 * 或显式剥离 CR/LF 控制字符后记录。
 */
public class LogInjectionMultiline {

    private static final Logger log = LoggerFactory.getLogger(LogInjectionMultiline.class);

    /**
     * 多跳：keyword -> msg 中间变量 -> 日志 sink。
     *
     * @param keyword 不可信输入（类比搜索框参数）
     */
    public void search(String keyword) {
        String msg = "search query executed: " + keyword;
        // 中间处理...
        // [CHECKPOINT id=JSEF-QL-002 cwe=117 level=L2 source=keyword sink=Logger.info expect=VULN]
        log.info(msg);
    }

    public static void main(String[] args) {
        new LogInjectionMultiline().search("laptop");
    }
}
