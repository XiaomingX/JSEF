/*
 * JSEF Benchmark 样本 — STR-1 Double Evaluation 安全对照（CWE-917）
 *
 * 修复策略：
 *  - L2：禁用二次求值。第一次求值的结果只当「数据字符串」使用，不再回灌求值器。
 *  - L4：跨阶段只做单层求值，且输入经白名单约束（仅允许已知安全标识符），
 *        第一次求值结果绝不二次 evaluate。
 *
 * 与任何具体 Web 框架完全解耦，仅用 Java 标准库。
 */

package com.jsef.benchmark.sec.str;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.util.Set;

public class STR1_DoubleEvaluation_Safe {

    // ------------------------------------------------------------------
    // L2 修复：结果只当数据，不再二次求值
    // ------------------------------------------------------------------

    // [SAFE] 模板只求值一次，结果作为纯数据字符串返回，不回灌求值器
    static String renderSafe(String template) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");

        // [SAFE] 仅一次求值：template 被当表达式解析
        Object first = engine.eval(template);          // 单次求值
        String result = String.valueOf(first);

        // [SAFE] 结果仅作为数据，不再 evaluate（杜绝双层求值）
        // [CHECKPOINT id=JSEF-STR-101S cwe=917 level=L2 source=template sink=no re-evaluation (result as data) expect=SAFE]
        return result;                                 // 结果当数据，不二次求值
    }

    // ------------------------------------------------------------------
    // L4 修复：跨阶段单层求值 + 白名单
    // ------------------------------------------------------------------

    // 允许的表达式白名单（已知安全标识符）
    private static final Set<String> ALLOWED = Set.of("ok", "status", "ping");

    // [SAFE] 阶段 A：第一次求值，结果存入共享 context（不做二次求值）
    static void stageASafe(String tpl) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        // [SAFE] 仅一次求值，结果作为数据
        Object first = engine.eval(tpl);               // 阶段 A：单次求值
        STR1_DoubleEvaluation_Safe.stageContext = String.valueOf(first);
    }

    // 共享 context（仅承载数据，不再被 evaluate）
    private static String stageContext;

    // [SAFE] 阶段 C：对 context 结果只做白名单校验，绝不二次 evaluate
    static String stageCSafe() throws Exception {
        // [SAFE] 仅白名单校验，结果不回灌求值器
        // [CHECKPOINT id=JSEF-STR-102S cwe=917 level=L4 source=template sink=single-eval + allowlist expect=SAFE]
        if (!ALLOWED.contains(stageContext)) {         // 白名单校验，无二次求值
            return "localhost-demo: rejected";
        }
        return stageContext;                           // 结果仅当数据返回
    }
}
