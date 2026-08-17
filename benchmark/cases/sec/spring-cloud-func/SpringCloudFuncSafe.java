package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L4 — Spring Cloud Function 安全对照
 *
 * 修复：禁用 routing-expression，使用固定路由名而非表达式。
 * SAFE 侧按实现判定安全。
 */
public class SpringCloudFuncSafe {

    public void route(String routingHeader) {
        String header = routingHeader;
        String fixedRoute = "fixedFunction";   // 固定路由名，忽略表达式头
        // [CHECKPOINT id=JSEF-NV509S cwe=917 level=L4 source=routing-expression header sink=SpEL.parseExpression expect=SAFE]
        dispatch(fixedRoute);
    }

    static void dispatch(String name) {
        System.out.println("[route] " + name);
    }

    public static void main(String[] args) {
        new SpringCloudFuncSafe().route("T(java.lang.Runtime).getRuntime().exec('id')");
    }
}
