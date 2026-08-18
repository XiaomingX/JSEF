// [VULN]
package com.jsef.benchmark.vuln.mspstatemachine;

/**
 * JSEF-Benchmark — 多步规划 P2：框架状态机 / @InitBinder 危险分支 (难度 L5, CWE-94)
 *
 * 题材抽象：Spring MVC 数据绑定状态机。DataBinder 是否允许把任意请求参数名映射为
 * 对象图路径，由绑定开关 {@code allowFieldBinding} 的状态机控制；开关开启时，
 * 攻击者控制的参数名被映射为对象图路径并喂入 EL/SpEL 求值（危险分支），
 * 开关关闭时仅允许白名单属性（安全分支）。
 *
 * ----------------------------------------------------------------------------
 * 长程任务子目标清单（需逐步规划才能给出可达性证明）：
 *   ① 识别绑定开关默认状态：allowFieldBinding 默认 true 才危险（状态机根因）。
 *   ② 追踪参数名 → 对象图路径映射：binder 把任意请求参数名映射为对象图路径
 *      （如 "theme.name" → 同名路径字符串）。
 *   ③ 判定状态机危险分支：开关开启时，映射出的路径被喂入 expressionParser 求值；
 *      开关关闭时仅允许白名单属性（安全分支）。
 *   ④ 产出可达性证明：当 allowFieldBinding=true 且攻击者控制参数名时，
 *      "theme.name" 路径可达 ExpressionParser.parseExpression sink。
 * ----------------------------------------------------------------------------
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本，所有 payload 仅为教学抽象。
 */
public class MvcBinderStateMachine {

    /**
     * 框架绑定开关（状态机根因）。默认 true = 危险；运维配置为 false 时走安全分支。
     */
    private boolean allowFieldBinding = true; // 状态机根因：默认危险

    /** 抽象表达式求值引擎（抽象 sink，不依赖真实 spring）。 */
    static class ExpressionParser {
        // 抽象：真实场景下即 SpEL/OGNL 求值器
        static Object parseExpression(String expression) {
            // sink 落点：对外部可控表达式求值
            System.out.println("[abstract eval] " + expression);
            return expression;
        }
    }

    /**
     * DataBinder 风格：把请求参数名 1:1 映射为对象图路径。
     * 单个绑定无害；危险在于映射出的路径被送进 ExpressionParser，且由开关状态门控。
     */
    private String mapParamToObjectPath(String paramName) {
        // 路径映射关键行：参数名直接成为对象图路径（不做 sanitize）
        return paramName;
    }

    /**
     * 绑定 + 求值入口。多步规划要求先判定开关状态再决定可达性。
     */
    public Object bindAndEvaluate(String paramName, String paramValue) {
        if (!allowFieldBinding) {
            // 安全分支：仅允许白名单属性
            if (!paramName.startsWith("safe.")) {
                return null;
            }
        }
        String objectPath = mapParamToObjectPath(paramName);
        // [CHECKPOINT id=JSEF-MSP-001 cwe=94 level=L5 source=attacker-controlled paramName sink=ExpressionParser.parseExpression expect=VULN trace=benchmark/cases/vuln/msp-statemachine/MvcBinderStateMachine.java:30,benchmark/cases/vuln/msp-statemachine/MvcBinderStateMachine.java:47,benchmark/cases/vuln/msp-statemachine/MvcBinderStateMachine.java:63]
        return ExpressionParser.parseExpression(objectPath + "=" + paramValue);
    }
}
