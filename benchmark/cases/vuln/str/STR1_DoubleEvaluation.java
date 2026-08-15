/*
 * JSEF Benchmark 样本 — STR-1 Double Evaluation（CWE-917，双层/二次求值）
 *
 * 维度抽象：从「表达式引擎双层求值」这一类历史漏洞中抽象出的「表达式机制 STR」
 * 原子范式，与任何具体 Web 框架完全解耦。本文件仅用 Java 标准库
 * （javax.script.ScriptEngine）模拟「双层求值」：表达式第一次求值的结果字符串仍含
 * 表达式语法，被再次解析执行。这是表达式引擎最独特、最难静态检测的特性——嵌套求值
 * （表达式求值结果再被当表达式二次解析）。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本，不连真实远端。
 * 危险调用以 "localhost-demo" 占位。
 */

package com.jsef.benchmark.vuln.str;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

public class STR1_DoubleEvaluation {

    // ------------------------------------------------------------------
    // L2 维度：单方法内的两次连续求值（render）
    // 第一次 evaluate(template) 得到结果字符串，结果仍含表达式语法，
    // 被第二次 evaluate(result) 再次解析 => 危险表达式在第二次求值触发。
    // ------------------------------------------------------------------

    // [VULN] 模板表达式被求值两次，第二次把第一次的结果当表达式再解析
    static Object render(String template) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");

        // [VULN] 第一次求值：template 被当表达式解析
        Object first = engine.eval(template);          // 第一次求值
        String result = String.valueOf(first);

        // [VULN] 第二次求值（双层）：第一次的结果字符串被再次当表达式解析
        // [CHECKPOINT id=JSEF-STR-101 cwe=917 level=L2 source=first-eval result (re-evaluated) sink=second evaluate() (double evaluation) expect=VULN]
        return engine.eval(result);                    // 第二次求值 => 危险表达式在此触发
    }

    // ------------------------------------------------------------------
    // L4 维度：跨阶段（stageA -> stageC）的双层求值
    // 用两个方法模拟「跨阶段」存储与二次解析：第一次求值结果存入共享
    // context，后续阶段再把结果二次 evaluate。污点跨方法/跨阶段流转。
    // 对应表达式引擎嵌套求值在分离的处理阶段间被二次解析。
    // ------------------------------------------------------------------

    // 共享 context：跨阶段保存第一次求值结果（模拟框架值栈）
    private static String stageContext;

    // [VULN] 阶段 A：第一次求值，结果存入共享 context
    static void stageA(String tpl) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        // [VULN] 第一次求值：模板被当表达式解析，结果落入 context
        Object first = engine.eval(tpl);               // 阶段 A：第一次求值（行A）
        stageContext = String.valueOf(first);
    }

    // [VULN] 阶段 C：把 context 中的结果二次 evaluate
    static Object stageC() throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        // [VULN] 第二次求值（跨阶段双层）：context 中的结果被再次当表达式解析
        // [CHECKPOINT id=JSEF-STR-102 cwe=917 level=L4 source=first-eval result (cross-stage) sink=second evaluate() expect=VULN trace=benchmark/cases/vuln/str/STR1_DoubleEvaluation.java:54,benchmark/cases/vuln/str/STR1_DoubleEvaluation.java:63]
        return engine.eval(stageContext);              // 阶段 C：第二次求值（行C）=> 危险表达式在此触发
    }
}
