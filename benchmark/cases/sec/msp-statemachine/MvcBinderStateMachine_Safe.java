// [VULN]（安全对照样本，expect=SAFE）
package com.jsef.benchmark.sec.mspstatemachine;

/**
 * JSEF-Benchmark — 多步规划 P2 安全对照 (难度 L5, CWE-94, expect=SAFE)
 *
 * 修复思路（对照 vuln 版本 MvcBinderStateMachine）：
 *   1) 绑定开关默认关闭 field 绑定（或 denyList 拒绝对象图路径）；
 *   2) 对参数名做 allowlist 校验，危险路径被拒，无法到达 ExpressionParser sink。
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class MvcBinderStateMachine_Safe {

    /** 安全默认值：关闭任意 field 绑定（状态机默认走安全分支）。 */
    private boolean allowFieldBinding = false; // 默认安全

    /** 参数名 allowlist：仅允许白名单前缀绑定/求值。 */
    private static final String[] ALLOWED_PREFIXES = {"safe.", "name.", "email."};

    static class ExpressionParser {
        static Object parseExpression(String expression) {
            return expression;
        }
    }

    private String mapParamToObjectPath(String paramName) {
        return paramName;
    }

    public Object bindAndEvaluate(String paramName, String paramValue) {
        if (allowFieldBinding) {
            String objectPath = mapParamToObjectPath(paramName);
            return ExpressionParser.parseExpression(objectPath + "=" + paramValue);
        }
        // 安全分支：先过 allowlist
        boolean allowed = false;
        for (String prefix : ALLOWED_PREFIXES) {
            if (paramName.startsWith(prefix)) {
                allowed = true;
                break;
            }
        }
        // [CHECKPOINT id=JSEF-MSP-001S cwe=94 level=L5 source=attacker-controlled paramName sink=allowlist reject expect=SAFE]
        if (!allowed) {
            return null; // 危险路径被拒，无法到达 sink
        }
        String objectPath = mapParamToObjectPath(paramName);
        return ExpressionParser.parseExpression(objectPath + "=" + paramValue);
    }
}
