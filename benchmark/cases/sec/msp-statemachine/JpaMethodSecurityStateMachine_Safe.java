// [VULN]（安全对照样本，expect=SAFE）
package com.jsef.benchmark.sec.mspstatemachine;

/**
 * JSEF-Benchmark — 多步规划 P2 安全对照 (难度 L5, CWE-285, expect=SAFE)
 *
 * 修复思路（对照 vuln 版本 JpaMethodSecurityStateMachine）：
 *   1) 方法安全开关默认开启，@PreAuthorize 表达式始终被求值；
 *   2) 低权限调用方被表达式拒绝，无法到达敏感操作。
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class JpaMethodSecurityStateMachine_Safe {

    /** 安全默认值：开启方法级安全（注解始终生效）。 */
    private boolean methodSecurityEnabled = true; // 默认安全

    static class SpelEvaluator {
        static boolean evaluate(String expression, String callerRole) {
            return expression.contains("ADMIN") && "ADMIN".equals(callerRole);
        }
    }

    public Object adminOperation(String callerRole) {
        String precondition = "hasRole('ADMIN')";
        if (methodSecurityEnabled) {
            if (!SpelEvaluator.evaluate(precondition, callerRole)) {
                return "DENIED";
            }
        }
        // [CHECKPOINT id=JSEF-MSP-002S cwe=285 level=L5 source=low-privilege callerRole sink=role check reject expect=SAFE]
        return doSensitiveAction();
    }

    private Object doSensitiveAction() {
        System.out.println("[abstract sensitive action] executed");
        return "OK";
    }
}
