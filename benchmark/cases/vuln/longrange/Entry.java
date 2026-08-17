package com.jsef.benchmark.vuln.longrange;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 长程链路 1 — 入口 / 执行模块（CWE-917 SpEL 表达式注入）
 *
 * 角色：模拟真实库的分层入口控制器。污点从不可信 HTTP 请求体出发，
 * 经 3 个编译单元、>= 5 个中间传递点，最终把表达式求值结果拼入
 * "可执行上下文"（此处语义桩为 bean 定义 / 动态查询）。
 *
 * 链路（跳数 >= 5）：
 *   1) HTTP @RequestBody requestBody            (source：不可信)
 *   2) Config.loadConfig(requestBody)           -> AppConfig（中间节点 1，Config.java:39）
 *   3) config.getExpression()                   -> 不可信 expression 文本（中间节点 2，Config.java:21）
 *   4) SpelParser.parseAndEvaluate(expr, root)  -> 构造 Expression + 求值（中间节点 3，SpelParser.java:38）
 *   5) expr.getValue(ctx)                       -> 携带污点的 Object（中间节点 4，SpelParser.java:40）
 *   6) 入口把结果拼入 bean/查询上下文            -> sink（本文件）
 *
 * 为什么是 L5（gadget chain 级）：单独看 Config 取值、SpelParser 求值都"像
 * 正常功能"；但当不可信请求体里的表达式被 Config 原样收下、再被 SpelParser
 * 以暴露内部方法的 EvaluationContext 求值时，跨越 config/解析/执行三模块的
 * 组合才形成表达式注入可达性。纯语法 SAST 难以识别这种跨模块组合危险。
 *
 * 安全底线：仅 localhost 演示，不写真实利用载荷。
 *
 * CWE-917 Expression Language Injection。
 */
@RestController
public class Entry {

    private final Config config = new Config();
    private final SpelParser spelParser = new SpelParser();

    @PostMapping("/benchmark/longrange/spel/unsafe")
    public String handle(@RequestBody String requestBody) {
        // 入口：不可信请求体进入链路
        Config.AppConfig cfg = config.loadConfig(requestBody);     // 传递点 2（见 Config.java:39）
        String expr = cfg.getExpression();                         // 传递点 3（见 Config.java:21）
        // 暴露内部方法的 root 对象（语义桩：真实库可能暴露 T() 可达类）
        BeanDefinitionRoot root = new BeanDefinitionRoot();
        Object evaluated = spelParser.parseAndEvaluate(expr, root); // 传递点 4-5（见 SpelParser.java:38,40）

        // [CHECKPOINT id=JSEF-LR-001 cwe=917 level=L5 source=@RequestBody requestBody sink=SpEL-evaluated value stitched into bean definition expect=VULN trace=benchmark/cases/vuln/longrange/Config.java:49,benchmark/cases/vuln/longrange/Config.java:28,benchmark/cases/vuln/longrange/SpelParser.java:37,benchmark/cases/vuln/longrange/SpelParser.java:39]
        return registerBean(String.valueOf(evaluated)); // 污点拼入"可执行上下文"（bean 定义/查询）
    }

    /** 语义等价：把表达式求值结果注册为 bean 定义 / 拼入动态查询（危险 sink）。 */
    static String registerBean(String value) {
        // 语义等价：DefaultListableBeanFactory.registerBeanDefinition(...)
        //          或 JpaRepository 动态查询拼接
        System.out.println("[bean-register] " + value);
        return "registered:" + value;
    }

    /** 求值上下文根对象（语义桩：暴露内部字段，演示 SpEL 可达性）。 */
    static class BeanDefinitionRoot {
        public String getName() {
            return "app";
        }
    }
}
