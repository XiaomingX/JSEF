// [VULN]（安全对照样本，expect=SAFE）
package com.jsef.benchmark.sec.longtask;

/**
 * JSEF-Benchmark — 长程任务 B 组 安全对照 (难度 L5, CWE-917, expect=SAFE)
 *
 * 修复思路（对照 vuln 版本 Spring4ShellStateMachine）：
 *   1) 绑定开关默认关闭 class.module.* 绑定（或明确 denyList 拒绝）；
 *   2) 对参数名做 allowlist 校验，class.module.classLoader 路径被拒，无法到达 SpEL sink。
 *
 * 题材抽象：Spring4Shell (CVE-2022-22965) 修复语义——通过 disallowedFields /
 * 属性名 allowlist 阻断危险对象图路径的绑定与求值。
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class Spring4ShellStateMachine_Safe {

    /**
     * 安全默认值：关闭 class.module 绑定开关（状态机默认走安全分支）。
     */
    private boolean bindClassModuleEnabled = false; // 默认安全

    /** 属性名 allowlist：仅允许白名单前缀绑定/求值。 */
    private static final String[] ALLOWED_PREFIXES = {"allowed.", "name.", "email."};

    static class SpelExpressionParser {
        static Object parseExpression(String expression) {
            return expression;
        }
    }

    private String mapParamToObjectPath(String paramName) {
        return paramName;
    }

    public Object handleBind(String paramName, String paramValue) {
        if (bindClassModuleEnabled) {
            String objectPath = mapParamToObjectPath(paramName);
            return SpelExpressionParser.parseExpression(objectPath + "=" + paramValue);
        }
        // 安全分支：先过 allowlist
        boolean allowed = false;
        for (String prefix : ALLOWED_PREFIXES) {
            if (paramName.startsWith(prefix)) {
                allowed = true;
                break;
            }
        }
        // [CHECKPOINT id=JSEF-LT-002S cwe=917 level=L5 source=class.module.classLoader path sink=allowlist reject expect=SAFE]
        if (!allowed) {
            return null; // class.module.classLoader 等路径被拒，无法到达 sink
        }
        String objectPath = mapParamToObjectPath(paramName);
        return SpelExpressionParser.parseExpression(objectPath + "=" + paramValue);
    }
}
