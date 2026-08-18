// [VULN]
package com.jsef.benchmark.vuln.mspstatemachine;

/**
 * JSEF-Benchmark — 多步规划 P2：方法级安全状态机 / @PreAuthorize SpEL 绕过 (难度 L5, CWE-285)
 *
 * 题材抽象：Spring Security 方法级授权。@PreAuthorize 上的 SpEL 表达式本应做权限校验，
 * 但其求值是否启用由状态机开关 {@code methodSecurityEnabled} 控制；开关关闭时注解被忽略，
 * 任意调用方都能直达业务方法（危险分支），开关开启时才真正校验角色。
 *
 * ----------------------------------------------------------------------------
 * 长程任务子目标清单（需逐步规划才能给出可达性证明）：
 *   ① 识别方法安全开关默认状态：methodSecurityEnabled 默认 false 才危险（状态机根因）。
 *   ② 解析 @PreAuthorize 上的权限表达式语义（如 hasRole('ADMIN')）。
 *   ③ 判定状态机危险分支：开关关闭时表达式求值被跳过，注解形同虚设。
 *   ④ 产出可达性证明：开关关闭且低权限调用方可达业务方法（越权）。
 * ----------------------------------------------------------------------------
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class JpaMethodSecurityStateMachine {

    /**
     * 方法安全开关（状态机根因）。默认 false = 危险（注解被忽略）；开启时才校验。
     */
    private boolean methodSecurityEnabled = false; // 状态机根因：默认危险

    /** 抽象 SpEL 求值器（用于模拟 @PreAuthorize 表达式求值）。 */
    static class SpelEvaluator {
        // 抽象：真实场景下即 MethodSecurityExpressionHandler
        static boolean evaluate(String expression, String callerRole) {
            // 语义等价：表达式要求 ADMIN，调用方角色不匹配则返回 false
            return expression.contains("ADMIN") && "ADMIN".equals(callerRole);
        }
    }

    /**
     * 受保护业务方法。多步规划要求先判定开关状态再决定可达性。
     */
    public Object adminOperation(String callerRole) {
        // 抽象 @PreAuthorize("hasRole('ADMIN')")
        String precondition = "hasRole('ADMIN')";
        if (methodSecurityEnabled) {
            // 安全分支：真正校验角色
            if (!SpelEvaluator.evaluate(precondition, callerRole)) {
                return "DENIED";
            }
        }
        // [CHECKPOINT id=JSEF-MSP-002 cwe=285 level=L5 source=low-privilege callerRole sink=unauthorized adminOperation expect=VULN trace=benchmark/cases/vuln/msp-statemachine/JpaMethodSecurityStateMachine.java:26,benchmark/cases/vuln/msp-statemachine/JpaMethodSecurityStateMachine.java:31,benchmark/cases/vuln/msp-statemachine/JpaMethodSecurityStateMachine.java:50]
        return doSensitiveAction(); // 开关关闭时低权限调用方直达敏感操作
    }

    private Object doSensitiveAction() {
        System.out.println("[abstract sensitive action] executed");
        return "OK";
    }
}
