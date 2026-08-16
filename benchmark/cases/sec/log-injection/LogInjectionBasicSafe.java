package com.jsef.benchmark.sec;

import java.util.logging.Logger;

/**
 * JSEF-Benchmark — 日志注入安全对照（CWE-117，SAFE）
 *
 * 安全做法：使用参数化日志 API（占位符 {}），框架会对不可信字段做转义，
 * 注入的换行符不会破坏日志行结构，伪造条目无法写入。
 *
 * 修复要点（对照 LogInjectionBasic.java）：参数化日志替代字符串拼接。
 */
public class LogInjectionBasicSafe {

    private static final Logger logger = Logger.getLogger(LogInjectionBasicSafe.class.getName());

    public void login(String username) {
        // [CHECKPOINT id=JSEF-QL-001S cwe=117 level=L1 source=username sink=Logger.info (parameterized) expect=SAFE]
        logger.info("User login attempt: {0}", username);
    }

    public static void main(String[] args) {
        new LogInjectionBasicSafe().login("alice");
    }
}
