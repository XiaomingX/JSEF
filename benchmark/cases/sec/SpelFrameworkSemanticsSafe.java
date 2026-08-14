package com.jsef.benchmark.sec;

/*
 * 运行态需 JSEF 依赖：本文件引用 org.springframework 框架类（@RequestParam、SimpleEvaluationContext 语义），
 * 用于静态分析 / LLM 阅读，不强求 mvn 编译通过，但语义正确、可读。
 *
 * JSEF-Benchmark L4 — SpelFrameworkSemantics 安全对照（SAFE 混淆样本）
 *
 * 安全做法：CVE-2022-22965 修复语义 —— 禁用 ClassLoader 等危险属性路径（disallowedFields），
 * 并使用 SimpleEvaluationContext（受限 SpEL，禁止类引用/方法调用）替代 StandardEvaluationContext。
 * 框架语义边界已被加固，污点无法到达危险 sink。用于计算 TN / FP。
 *
 * CWE-917 Expression Language Injection。
 */

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.web.bind.annotation.RequestParam;

public class SpelFrameworkSemanticsSafe {

    public static class BindTarget {
        private Object classLoader;
        public Object getClassLoader() { return classLoader; }
        public void setClassLoader(Object v) { this.classLoader = v; }
    }

    public void bindAndEvaluate(@RequestParam("class.module.classLoader") String paramName) {
        BindTarget target = new BindTarget();
        // 安全：disallowedFields 阻断 class.module.classLoader 路径写入
        // (框架语义：DataBinder.setDisallowedFields("class.*","*.classLoader"))
        if (paramName.contains("classLoader") || paramName.contains("class.module")) {
            throw new IllegalArgumentException("disallowed property path");
        }
        target.setClassLoader(paramName);

        // 安全 sink：SimpleEvaluationContext 受限，禁止类型引用与方法调用
        // [CHECKPOINT id=JSEF-TP-005S cwe=917 level=L4 source=@RequestParam(class.module.classLoader) sink=SimpleEvaluationContext expect=SAFE]
        EvaluationContext safeCtx = SimpleEvaluationContext.forReadWriteDataBinding().build();
        // spelParser.parseExpression(expr).getValue(safeCtx) —— 受限上下文，无类加载器可达
    }

    public static void main(String[] args) {
        new SpelFrameworkSemanticsSafe().bindAndEvaluate("localhost-demo");
    }
}
