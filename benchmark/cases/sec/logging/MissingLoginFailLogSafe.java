package com.jsef.benchmark.sec.logging;

import java.time.Instant;

/**
 * JSEF Benchmark — A09 安全对照（CWE-778，L2）
 *
 * SAFE：登录失败时记录 who（用户名）、where（来源 IP）、when（时间）。
 */
public class MissingLoginFailLogSafe {

    /**
     * SAFE：登录失败记录完整上下文。
     */
    public static boolean login(String user, String pwd, String clientIp) {
        boolean ok = "secret".equals(pwd);
        if (!ok) {
            // source：认证失败事件
            // [CHECKPOINT id=JSEF-A09-001S cwe=778 level=L2 source=login failure event sink=audit log (who/where/when) expect=SAFE]
            System.out.println("[AUDIT] LOGIN_FAIL user=" + user
                    + " ip=" + clientIp + " at=" + Instant.now());
            return false;
        }
        return true;
    }
}
