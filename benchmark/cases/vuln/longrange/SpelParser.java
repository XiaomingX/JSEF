package com.jsef.benchmark.vuln.longrange;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

/**
 * JSEF-Benchmark L5 长程链路 1 — 解析/转换模块（CWE-917 SpEL 表达式注入）
 *
 * 角色：模拟真实库的"表达式解析层"。从 config 模块拿到不可信 expression 文本，
 * 用 Spring SpEL 解析器求值。真实库常用它做动态路由 / 动态查询 / 模板求值。
 *
 * 污点流入：AppConfig.expression（来自 Config 模块，攻击者控制）。
 * 污点流出：SpelParser 把表达式求值后的结果（Object）回传给入口模块，
 *          入口模块随后把该结果拼入"可执行上下文"（bean 定义 / 查询）。
 *
 * 危险点：把不可信文本直接喂给 SpEL parser 且使用 RootObject 暴露的
 *         方法/字段，等于给攻击者一个表达式执行入口（SpEL 可调用任意
 *         T(java.lang.Runtime).getRuntime().exec(...)）。
 *
 * 安全底线：仅 localhost 演示，不写真实利用载荷。
 */
public class SpelParser {

    private final ExpressionParser parser = new SpelExpressionParser();

    /**
     * 把不可信 expression 当作 SpEL 解析并求值。
     *
     * @param rawExpression 不可信表达式文本（来自 config 模块）
     * @param root          求值上下文的根对象（暴露内部字段/方法）
     * @return 表达式求值结果（污点继续向下游传递）
     */
    public Object parseAndEvaluate(String rawExpression, Object root) {
        StandardEvaluationContext ctx = new StandardEvaluationContext(root); // 中间传递点 3
        // 中间传递点 4：不可信文本直接构造 SpEL 表达式对象
        org.springframework.expression.Expression expr = parser.parseExpression(rawExpression);
        // 中间传递点 5：求值，结果携带污点（可能被 T(...).exec 控制）
        return expr.getValue(ctx);
    }
}
