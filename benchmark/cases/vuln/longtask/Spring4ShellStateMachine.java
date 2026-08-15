// [VULN]
package com.jsef.benchmark.vuln.longtask;

/**
 * JSEF-Benchmark — 长程任务 B 组：框架状态机 / 绑定语义 (难度 L5, CWE-917)
 *
 * 题材抽象：Spring4Shell (CVE-2022-22965) 的"状态机 + 绑定语义"危险本质。
 * 不依赖真实 spring 依赖——用模拟方法 + 注释表达语义即可。
 *
 * ----------------------------------------------------------------------------
 * 长程任务子目标清单（需逐步规划才能给出可达性证明）：
 *   ① 识别绑定开关状态：bindClassModuleEnabled 默认 true 才危险（L5 状态机根因）。
 *   ② 追踪参数名 → 对象图路径映射：dataBinder 把任意请求参数名映射为对象图路径
 *      （如 "class.module.classLoader..." 直达 ClassLoader 属性）。
 *   ③ 判定状态机危险分支：开关开启时，映射出的路径被喂入 SpEL 求值（危险分支）；
 *      开关关闭时仅允许白名单属性（安全分支）。
 *   ④ 产出可达性证明：当 bindClassModuleEnabled=true 且攻击者控制参数名时，
 *      class.module.classLoader 路径可达 SpelExpressionParser.parseExpression sink。
 * ----------------------------------------------------------------------------
 *
 * 预期可达性证明中间产物（file:line 节点序列）：
 *   - benchmark/cases/vuln/longtask/Spring4ShellStateMachine.java:<bindClassModuleEnabled 声明行>
 *   - benchmark/cases/vuln/longtask/Spring4ShellStateMachine.java:<dataBinder 路径映射行>
 *   - benchmark/cases/vuln/longtask/Spring4ShellStateMachine.java:<状态机分支判定行>
 *   - benchmark/cases/vuln/longtask/Spring4ShellStateMachine.java:<SpEL sink 行>
 *   （以上行号为真实源码行，见下方 trace 字段。）
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本，
 * 不提供针对真实目标的 RCE 利用，所有 payload 仅为教学抽象表达。
 */
public class Spring4ShellStateMachine {

    /**
     * 框架绑定开关（状态机根因）。
     * 默认 true = 危险；当运维配置为 false 时走安全分支。
     */
    private boolean bindClassModuleEnabled = true; // 状态机根因：默认危险

    /** 模拟 SpEL 求值引擎（抽象 sink，不依赖真实 spring）。 */
    static class SpelExpressionParser {
        // 抽象：真实场景下即 org.springframework.expression.spel.standard.SpelExpressionParser
        static Object parseExpression(String expression) {
            // sink 落点：对外部可控表达式求值
            System.out.println("[abstract SpEL eval] " + expression);
            return expression;
        }
    }

    /**
     * DataBinder 风格：把请求参数名 1:1 映射为对象图路径。
     * 例：paramName="class.module.classLoader.resources.context" -> 同名路径字符串。
     * 单个绑定无害；危险在于映射出的路径被送进 SpEL，且由开关状态门控。
     */
    private String mapParamToObjectPath(String paramName) {
        // 路径映射关键行：参数名直接成为对象图路径（不做 sanitize）
        return paramName; // 例如 "class.module.classLoader..."
    }

    /**
     * 处理绑定请求（入口）。
     * @param paramName   攻击者部分可控的请求参数名
     * @param paramValue  攻击者可控的值（此处仅影响表达式内容）
     */
    public Object handleBind(String paramName, String paramValue) {
        // 状态机分支判定：开关决定是否允许 class.module.* 路径进入求值
        if (bindClassModuleEnabled) {
            // 危险分支：任意映射路径直达 SpEL sink
            String objectPath = mapParamToObjectPath(paramName);
            // [CHECKPOINT id=JSEF-LT-002 cwe=917 level=L5 source=class.module.classLoader path under enabled flag sink=SpelExpressionParser.parseExpression expect=VULN trace=benchmark/cases/vuln/longtask/Spring4ShellStateMachine.java:56,benchmark/cases/vuln/longtask/Spring4ShellStateMachine.java:70]
            return SpelExpressionParser.parseExpression(objectPath + "=" + paramValue);
        } else {
            // 安全分支：仅白名单属性，class.module.* 被拒，无法到达 sink
            if (!paramName.startsWith("allowed.")) {
                return null;
            }
            String objectPath = mapParamToObjectPath(paramName);
            return SpelExpressionParser.parseExpression(objectPath + "=" + paramValue);
        }
    }
}
