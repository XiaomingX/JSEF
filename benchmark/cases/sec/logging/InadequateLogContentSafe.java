package com.jsef.benchmark.sec.logging;

import java.time.Instant;

/**
 * JSEF Benchmark — A09 安全对照（CWE-532，L2）
 *
 * SAFE：日志包含完整上下文（who/where/what/when）。
 */
public class InadequateLogContentSafe {

    /**
     * SAFE：记录含完整上下文的安全动作日志。
     */
    public static void onAction(String user, String clientIp, String action) {
        // source：安全相关动作事件
        // [CHECKPOINT id=JSEF-A09-002S cwe=532 level=L2 source=security action event sink=log (with user/ip/action/time) expect=SAFE]
        System.out.println("[AUDIT] action=" + action
                + " user=" + user + " ip=" + clientIp + " at=" + Instant.now());
    }
}
