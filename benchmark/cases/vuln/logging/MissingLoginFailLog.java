package com.jsef.benchmark.vuln.logging;

/**
 * JSEF Benchmark — A09 安全日志与监控失败（CWE-778，L2）
 *
 * 场景：用户登录失败时既不记录也不告警，攻击者可持续暴力破解或撞库
 * 而无法被审计发现。
 *
 * 为何危险：缺少认证失败日志，意味着无法检测凭据填充、暴力破解，
 * 也无法事后溯源；监控失败是 A09 的核心。
 *
 * 安全底线：仅 localhost 演示语义。
 */
public class MissingLoginFailLog {

    /**
     * VULN：登录失败直接返回，无任何日志/告警。
     */
    public static boolean login(String user, String pwd) {
        boolean ok = "secret".equals(pwd);
        if (!ok) {
            // source：认证失败事件
            // [CHECKPOINT id=JSEF-A09-001 cwe=778 level=L2 source=login failure event sink=no audit log (return silently) expect=VULN]
            return false;   // 静默返回，登录失败无记录
        }
        return true;
    }
}
