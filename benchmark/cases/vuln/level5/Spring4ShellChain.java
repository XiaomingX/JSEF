package com.jsef.benchmark.vuln;

/*
 * 运行态需 JSEF 依赖：本文件引用 org.springframework 框架类（DataBinder / class.module 语义），
 * 用于静态分析 / LLM 阅读，不强求 mvn 编译通过，但语义正确、可读。
 *
 * JSEF-Benchmark L5 — gadget chain（Spring4Shell 抽象，CVE-2022-22965）
 *
 * 难度：L5（gadget chain / 框架语义组合）。多个单独"无害"的框架绑定语义组合成危险可达性：
 *   - 攻击者通过 HTTP 参数名 `class.module.classLoader.URLs[0]` 这类属性路径，
 *     经 Spring DataBinder 的驼峰/点号映射写入对象图（无害映射单看是正常绑定）；
 *   - 再经 ClassLoader 属性链到达可写字段（无害的 JavaBean 属性访问）；
 *   - 当这些绑定路径被拼成 SpEL 求值表达式（sink）时，形成任意写入/命令执行可达性。
 *
 * 关键点：单条绑定无害，组合成 class.module.classLoader 路径后到达 SpEL sink 才危险。
 * 纯语法 SAST 难以识别跨多层框架属性映射才危险的链路。
 *
 * CWE-917 Expression Language Injection。
 * 安全底线：仅展示属性路径链语义，Payload 仅 localhost 演示，不提供真实利用脚本。
 */

import org.springframework.web.bind.annotation.RequestParam;

/**
 * JSEF-Benchmark L5 — class.module.classLoader 属性链抽象到 SpEL。
 */
public class Spring4ShellChain {

    // 框架绑定目标（抽象 class/module/classLoader 的 JavaBean 结构）
    public static class Module { public Object classLoader; }
    public static class Clazz { public Module module; }

    /**
     * 模拟框架把任意参数名映射为对象图路径，再送入 SpEL 求值。
     *
     * @param propPath 攻击者可控的属性路径（如 class.module.classLoader.URLs）
     */
    public void bindAndEval(@RequestParam("class.module.classLoader") String propPath) {
        Clazz target = new Clazz();
        target.module = new Module();
        target.module.classLoader = propPath; // 框架语义：属性路径写入对象图

        // 组合可达性：属性路径链 -> SpEL 求值（sink）
        // [CHECKPOINT id=JSEF-L5-S4S-001 cwe=917 level=L5 source=class.module.classLoader path sink=SpelExpressionParser.parseExpression expect=VULN]
        parseExpression(String.valueOf(target.module.classLoader));
    }

    // 抽象 sink：框架对属性路径求值。运行态需 org.springframework.expression 依赖。
    private static Object parseExpression(String expr) {
        System.out.println("[spel-eval] " + expr);
        return null;
    }

    public static void main(String[] args) {
        new Spring4ShellChain().bindAndEval("localhost-demo");
    }
}
