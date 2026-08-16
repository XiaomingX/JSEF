package com.jsef.benchmark.vuln;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-917 / CWE-502 Log4j2 JNDI 注入（教学级触发点演示，不含利用链）：
 * 当 Log4j2 未关闭 message lookup 时，日志内容中的 ${jndi:...} 占位符
 * 会被解析，可能触发远程类加载。本样本仅展示"不可信输入进入日志"的 sink 触发点，
 * 不含任何可连接的 LDAP/RMI 服务器地址，不提供恶意 payload。
 *
 * 修复（见 sec）：升级 Log4j2 >= 2.15.0（默认关闭 lookup），
 * 或显式设置 -Dlog4j2.formatMsgNoLookups=true，并对日志参数做白名单过滤。
 */
@RestController
public class Log4j2JndiInjection {

    private static final Logger logger = LogManager.getLogger(Log4j2JndiInjection.class);

    @GetMapping("/api/v1/log4j2/unsafe/log")
    public String log(@RequestParam String userInput) {
        // [CHECKPOINT id=JSEF-COMP-008 cwe=917 level=L2 source=userInput param sink=logger.info (JNDI lookup) expect=VULN]
        logger.info("user action: " + userInput); // 未关闭 lookup 时 ${jndi:...} 可触发
        return "logged";
    }
}
