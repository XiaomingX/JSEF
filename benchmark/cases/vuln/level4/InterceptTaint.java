package com.jsef.benchmark.vuln;

/*
 * 运行态需 JSEF 依赖：本文件引用 org.springframework 框架类（HandlerInterceptor 语义），
 * 用于静态分析 / LLM 阅读，不强求 mvn 编译通过，但语义正确、可读。
 *
 * JSEF-Benchmark L4 — 框架语义依赖（拦截器跨层注入污点到 SpEL）
 *
 * 难度：L4（框架语义/跨层）。HandlerInterceptor.preHandle 在控制器之前执行，
 * 从请求头提取污点写入请求属性（request attribute）；后续 Controller/Service 读取该属性
 * 并送入 SpEL 求值（sink）。污点跨越"拦截器层 -> 控制层"两个框架层，
 * 纯语法工具若不理解拦截器生命周期与属性传递，会丢失 source。
 *
 * CWE-917 Expression Language Injection。
 *
 * 安全底线：仅展示拦截器-控制器跨层语义，Payload 仅 localhost 演示，不提供真实利用脚本。
 */

import org.springframework.web.servlet.HandlerInterceptor;

/**
 * JSEF-Benchmark L4 — HandlerInterceptor 注入污点后跨层到达 SpEL。
 */
public class InterceptTaint implements HandlerInterceptor {

    /**
     * 拦截器 preHandle：从请求头写入污点到请求属性（框架语义 source）。
     * 真实语义：request.setAttribute("expr", request.getHeader("X-Expr"))。
     */
    public void preHandle(Object request) {
        // 框架语义：从请求头提取不可信值并存入 request attribute
        setAttribute(request, "expr", getHeader(request, "X-Expr"));
    }

    /**
     * 控制层读取拦截器写入的属性并送入 SpEL 求值（sink）。
     * 真实语义：String expr = (String) request.getAttribute("expr");
     *          new SpelExpressionParser().parseExpression(expr).getValue();
     */
    public void handle(Object request) {
        String expr = (String) getAttribute(request, "expr"); // 污点来自拦截器层
        // [CHECKPOINT id=JSEF-L4-INT-001 cwe=917 level=L4 source=interceptor-injected request attribute sink=SpelExpressionParser.parseExpression expect=VULN]
        parseExpression(expr);
    }

    // 抽象 sink：框架对表达式求值。运行态需 org.springframework.expression 依赖。
    private static Object parseExpression(String expr) {
        System.out.println("[spel-eval] " + expr);
        return null;
    }

    // 抽象方法：表达拦截器-请求属性的框架语义
    private static void setAttribute(Object req, String k, String v) { /* framework semantics */ }
    private static String getAttribute(Object req, String k) { return "localhost-demo"; }
    private static String getHeader(Object req, String k) { return "localhost-demo"; }

    public static void main(String[] args) {
        InterceptTaint t = new InterceptTaint();
        Object req = new Object();
        t.preHandle(req);
        t.handle(req);
    }
}
