package com.jsef.benchmark.vuln.cascade;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark 样本族 B — 级联信任：多实体网络推理的权限决策（CWE-285，L5）
 *
 * 难度：L5（跨两个系统的配置→决策级联，单看任一侧都不致命）
 *
 * 链路（级联信任，多实体网络推理）：
 *   1) 系统 A 的 featureFlag 来自不可信配置来源并被改写
 *      （source：配置开关被不可信来源改写，见 ConfigService.java:56）
 *   2) 系统 B 的 AccessDecision 无条件信任该开关决定是否放行 admin
 *      （中间节点：决策依据信任断言，见 AccessDecision.java:29）
 *   3) FeatureGateAdmin 据决策结果直接放行管理员操作                (sink)
 *
 * 为什么是"级联信任 / 多实体网络推理"：系统 A 的配置状态（featureFlag）决定
 * 系统 B 的权限决策。单独分析系统 A：一个"读配置返回字符串"的正常方法；
 * 单独分析系统 B：一个"读开关给权限"的正常 RBAC 决策。两者单看都像安全
 * 功能，但组合起来——A 的配置可被外部改写、B 又不对开关做任何调用方
 * 校验/二次确认——形成跨实体的权限放行可达性。SAST 需要跨两个系统的
 * 信任网络推理才能判定 CWE-285（Improper Authorization）。
 *
 * 修复要点：功能开关只能来自可信管理通道，且权限放行必须结合调用者
 * 身份/上下文二次校验，不能仅凭单一可改写开关。
 *
 * 安全底线：仅 localhost 演示，不写真实攻击载荷。
 */
@RestController
public class FeatureGateAdmin {

    private final ConfigService config = new ConfigService();
    private final AccessDecision accessDecision = new AccessDecision();

    /**
     * 危险入口：凭被改写的 featureFlag 放行管理员权限。
     */
    @PostMapping("/benchmark/cascade/feature/admin")
    public String adminEndpoint() {
        // 入口：读取系统 A 的配置开关（source，见 ConfigService.java:56）
        String featureFlag = config.readFeatureFlag();
        // 中间节点：系统 B 据此做权限决策（见 AccessDecision.java:29）
        boolean granted = accessDecision.allowAdmin(featureFlag);

        // [CHECKPOINT id=JSEF-OS-003 cwe=285 level=L5 source=rewritten config featureFlag sink=admin action granted on single trusted switch expect=VULN trace=benchmark/cases/vuln/cascade/ConfigService.java:56,benchmark/cases/vuln/cascade/AccessDecision.java:29]
        return doAdminAction(granted); // 授权放行：凭可改写开关决定高危权限
    }

    /**
     * 语义等价：执行管理员操作（危险 sink，仅被放行时可达）。
     */
    static String doAdminAction(boolean granted) {
        if (granted) {
            System.out.println("[admin-action] granted by cascade trust");
            return "ADMIN_OK";
        }
        return "DENIED";
    }
}
