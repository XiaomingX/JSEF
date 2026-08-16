package com.jsef.benchmark.sec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-917 / CWE-502 修复：使用参数化日志（占位符），并依赖已关闭 lookup 的安全配置
 * （Log4j2 >= 2.15.0 默认关闭，或 -Dlog4j2.formatMsgNoLookups=true），
 * 用户输入不会被当作查找表达式解析。
 */
@RestController
public class Log4j2JndiInjectionSafe {

    private static final Logger logger = LogManager.getLogger(Log4j2JndiInjectionSafe.class);

    @GetMapping("/api/v1/log4j2/safe/log")
    public String log(@RequestParam String userInput) {
        // [CHECKPOINT id=JSEF-COMP-008S cwe=917 level=L2 source=userInput param sink=logger.info (lookup disabled) expect=SAFE]
        logger.info("user action: {}", userInput); // 参数化 + lookup 关闭
        return "logged safely";
    }
}
