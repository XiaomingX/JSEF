package com.jsef.benchmark.vuln;

/*
 * 运行态需 JSEF 依赖：本文件引用 org.springframework 框架类（@RequestParam、DataBinder 语义），
 * 用于静态分析 / LLM 阅读，不强求 mvn 编译通过，但语义正确、可读。
 *
 * JSEF-Benchmark L4 — 框架语义依赖（SpEL 注入，CVE-2022-22965 Spring4Shell 抽象）
 *
 * 难度：L4（框架语义）。纯语法工具认不出此漏洞，因为它依赖 Spring 运行时语义：
 *   @RequestParam 绑定到字段名 → Spring DataBinder 用驼峰映射把 HTTP 参数名映射到 JavaBean 属性
 *   → 攻击者通过 `class.module.classLoader...` 这类属性路径驱动 SpEL/反射求值（sink）。
 * 污点不是直接"变量赋值"，而是框架在绑定阶段隐式地把任意参数名当作属性路径写入对象图，
 * 再经框架内部 SpEL/反射到达危险 sink。CAP-09 框架语义理解专用样本。
 *
 * CWE-917 Expression Language Injection。
 *
 * 安全底线：仅展示绑定语义，Payload 仅 localhost 演示，不提供真实利用脚本。
 */

import org.springframework.web.bind.annotation.RequestParam;

public class SpelFrameworkSemantics {

    // 框架绑定目标：Spring 会把 HTTP 参数名映射到该 JavaBean 的属性
    public static class BindTarget {
        private Object classLoader;          // 框架语义：class.module.classLoader 路径可达
        public Object getClassLoader() { return classLoader; }
        public void setClassLoader(Object v) { this.classLoader = v; }
    }

    /**
     * 模拟 @RequestParam 驱动的 DataBinder 绑定：
     * 参数名（如 "class.module.classLoader.URLs"）经驼峰/点号映射写入目标对象图，
     * 随后框架内部对写入的值做 SpEL 求值 —— 污点来自参数名而非参数值，纯语法分析难追踪。
     *
     * @param paramName HTTP 参数名（框架语义 source：任意属性路径）
     */
    public void bindAndEvaluate(@RequestParam("class.module.classLoader") String paramName) {
        BindTarget target = new BindTarget();
        // 框架语义：DataBinder 隐式把 paramName 当作属性路径写入对象图
        target.setClassLoader(paramName);

        // 框架内部 sink：SpEL 对绑定的属性值/路径求值（CVE-2022-22965 抽象）
        // [CHECKPOINT id=JSEF-TP-005 cwe=917 level=L4 source=@RequestParam(class.module.classLoader) sink=SpelEvaluationContext/parseExpression expect=VULN]
        evaluateAsSpel(String.valueOf(target.getClassLoader()));
    }

    // 抽象 sink：框架内部对绑定值做 SpEL 求值。运行态需 org.springframework.expression 依赖。
    private void evaluateAsSpel(String expr) {
        // 语义等价：SpelExpressionParser().parseExpression(expr).getValue()
        // 此处仅以注释表达框架语义，不引入真实解析以避免本地编译依赖。
        System.out.println("[framework-semantics-spel-eval] " + expr);
    }

    public static void main(String[] args) {
        new SpelFrameworkSemantics().bindAndEvaluate("localhost-demo");
    }
}
