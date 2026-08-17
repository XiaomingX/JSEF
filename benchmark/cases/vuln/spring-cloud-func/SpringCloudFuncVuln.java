package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L4 — Spring Cloud Function routing-expression 注入
 *
 * 难度：L4（跨文件 / 框架语义）。请求头 spring.cloud.function.routing-expression
 * 被框架直接作为 SpEL 路由表达式求值。不可信 header 进入表达式 sink，污点经
 * HTTP header → 框架路由 → SpEL 求值跨多个框架层，纯语法 SAST 难以识别该隐式
 * 框架语义。
 *
 * CWE-917 (Expression Language Injection)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 SpringCloudFuncSafe.java）：禁用 routing-expression 或固定路由名。
 */
public class SpringCloudFunc {

    /**
     * @param routingHeader 请求头 spring.cloud.function.routing-expression 的值
     */
    public void route(String routingHeader) {
        String header = routingHeader;            // header 读取（trace 节点①）
        // [CHECKPOINT id=JSEF-NV509 cwe=917 level=L4 source=routing-expression header sink=SpEL.parseExpression expect=VULN trace=benchmark/cases/vuln/spring-cloud-func/SpringCloudFuncVuln.java:22,benchmark/cases/vuln/spring-cloud-func/SpringCloudFuncVuln.java:24]
        parseExpression(header);                  // 直接作为 SpEL 求值（trace 节点②）
    }

    // 抽象 sink：语义等价 SpelExpressionParser.parseExpression(expr).getValue()
    static void parseExpression(String expr) {
        System.out.println("[spel-eval] " + expr);
    }

    public static void main(String[] args) {
        new SpringCloudFunc().route("T(java.lang.Runtime).getRuntime().exec('id')");
    }
}
