package com.jsef.benchmark.sec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JSEF-Benchmark — 日志注入多行伪造安全对照（CWE-117，SAFE）
 *
 * 安全做法：记录前剥离 CR/LF 控制字符，使注入无法换行伪造。
 *
 * 修复要点（对照 LogInjectionMultiline.java）：净化不可信字段的控制字符。
 */
public class LogInjectionMultilineSafe {

    private static final Logger log = LoggerFactory.getLogger(LogInjectionMultilineSafe.class);

    public void search(String keyword) {
        String sanitized = keyword.replaceAll("[\\r\\n]", "");
        String msg = "search query executed: " + sanitized;
        // [CHECKPOINT id=JSEF-QL-002S cwe=117 level=L2 source=keyword sink=Logger.info (sanitized) expect=SAFE]
        log.info(msg);
    }

    public static void main(String[] args) {
        new LogInjectionMultilineSafe().search("laptop");
    }
}
