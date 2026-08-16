package com.jsef.benchmark.vuln;

import java.util.logging.Logger;

/**
 * JSEF-Benchmark — 日志注入 / 日志伪造（CWE-117，L1 单跳）
 *
 * 不可信用户输入不加净化和转义，直接拼入日志语句，攻击者可注入换行
 * （\r\n）与伪造的日志条目（如 "DEBUG admin login OK"），污染审计日志、
 * 掩盖真实攻击轨迹，干扰 SIEM / SOC 告警。
 *
 * CodeQL 对应查询：java/log-injection（JNDI/日志注入套件）。
 *
 * 安全底线：仅 localhost 教学演示，不提供真实日志篡改利用脚本。
 *
 * 修复要点（对照 LogInjectionBasicSafe.java）：对不可信数据做转义/结构化
 * 字段化记录（如 MDC / 键值对），或使用参数化日志 API 而非字符串拼接。
 */
public class LogInjectionBasic {

    private static final Logger logger = Logger.getLogger(LogInjectionBasic.class.getName());

    /**
     * 单跳：不可信用户名直接拼入日志（sink）。
     *
     * @param username 不可信输入（类比 HTTP 请求参数）
     */
    public void login(String username) {
        // 模拟登录处理...
        // [CHECKPOINT id=JSEF-QL-001 cwe=117 level=L1 source=username sink=Logger.info expect=VULN]
        logger.info("User login attempt: " + username);
    }

    public static void main(String[] args) {
        new LogInjectionBasic().login("alice");
    }
}
