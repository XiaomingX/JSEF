package com.jsef.benchmark.vuln.cascade;

/**
 * JSEF-Benchmark 样本族 B — 级联信任：权限决策服务桩（中间层）
 *
 * 角色：模拟系统 B 的"访问决策器"。本文件不设独立 checkpoint，
 * 仅作为 FeatureGateAdmin 级联信任链路的 trace 节点存在。
 *
 * 污点流：AccessDecision 根据系统 A 的 featureFlag 决定是否放行 admin
 * 权限。featureFlag 由 ConfigService 从不可信来源读取并改写，本服务
 * 无条件信任该开关，据此放行危险权限。
 *
 * 为什么这里是合理非缺陷：辅助类不单独计 checkpoint，它只是主链路上的
 * 一个传递/决策节点；真正的判定点（sink，授权放行）在 FeatureGateAdmin。
 * 被测工具应沿级联信任链把本文件的"开关决定放行"识别为链路中间态。
 *
 * 安全底线：仅 localhost 演示，不写真实攻击载荷。
 */
public class AccessDecision {

    /**
     * 根据 featureFlag 决定是否放行 admin 权限（语义桩：真实 RBAC 决策）。
     *
     * @param featureFlag 系统 A 的可信配置开关（已被不可信来源改写）
     * @return 是否放行管理员权限
     */
    public boolean allowAdmin(String featureFlag) {
        // 中间节点：决策依据 = 被改写的 featureFlag（信任断言）
        boolean granted = "enabled".equalsIgnoreCase(featureFlag);
        System.out.println("[access-decision] adminGranted=" + granted);
        return granted;
    }
}
