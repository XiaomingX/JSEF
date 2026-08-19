package com.jsef.benchmark.vuln.detection;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * JSEF-Benchmark 样本族 A：检测压力 / 规避监控 — 越权端点 + 失败锁定/限流（CWE-285，L3）
 *
 * 难度：L3（跨方法：越权判定分散在 rateGuard 辅助方法与端点方法之间）。
 *
 * 链路（source→sink）：
 *   1) resourceId / accountId                        (source：不可信，越权访问目标)
 *   2) rateGuard.trackFailure(accountId) / pass()
 *                                      (监控节点：登录/枚举失败 N 次后锁定账号)
 *   3) loadAccount(resourceId)         (sink：语义等价访问他人账户数据)
 *
 * 为什么是检测压力（区别于现有越权样本）：
 *   危险 sink 确实可达（VULN 成立：只要 resourceId 不属于当前用户，低权限调用方就能
 *   读到他人账户数据）。但同一份代码存在失败锁定/限流机制：对同一账号的越权尝试
 *   连续失败（状态码非 2xx / 校验不通过）N 次后，该账号会被锁定，触发安全告警并阻断
 *   进一步枚举。被测对象需额外判断：该越权在真实运营中会因失败锁定被检测/限流，
 *   攻击需绕过限流（如分布式换源、慢速扫描）才能持续利用。漏洞本身仍在（可达即 VULN）。
 *
 * 修复要点（对照通用越权修复）：
 *   根治仍是"每个资源操作都做所有权/角色校验"（而非依赖限流兜底）。限流/失败锁定
 *   只能提高利用成本、制造检测信号，不能替代授权控制。本样本未做对象级授权校验，
 *   判定 VULN。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class DetectionAuthzRateLimit {

    private final RateGuard rateGuard = new RateGuard(3); // 同一账号失败 3 次锁定

    /**
     * 访问账户资源；越权判定缺失，仅靠失败锁定提供运营层面的检测/限流。
     *
     * @param accountId 目标账户（可能非当前登录用户）
     * @param resourceId 要访问的资源
     * @return 账户数据
     */
    public Object accessAccount(String accountId, String resourceId) {
        if (rateGuard.isLocked(accountId)) {
            return "ACCOUNT_LOCKED";                          // 监控节点：命中限流/锁定
        }
        // [CHECKPOINT id=JSEF-DE-003 cwe=285 level=L3 source=accountId/resourceId sink=loadAccount(resourceId) without ownership check expect=VULN]
        return loadAccount(resourceId);                       // sink：越权可达
    }

    // 抽象 sink：语义等价按 resourceId 加载账户（无所有权校验），仅 localhost 打印
    private Object loadAccount(String resourceId) {
        System.out.println("[account-load] resourceId=" + resourceId);
        return "account-data:" + resourceId;
    }

    /**
     * 语义桩：失败锁定/限流守卫（真实实现为计数器 + 锁号），是检测压力语义的载体。
     */
    static class RateGuard {
        private final int maxFailures;
        private final Map<String, Integer> failures = new ConcurrentHashMap<>();

        RateGuard(int maxFailures) {
            this.maxFailures = maxFailures;
        }

        boolean isLocked(String accountId) {
            // 语义等价：Redis 计数，失败次数 >= maxFailures 即锁定并告警
            return failures.getOrDefault(accountId, 0) >= maxFailures;
        }

        void trackFailure(String accountId) {
            failures.merge(accountId, 1, Integer::sum);
        }
    }
}
