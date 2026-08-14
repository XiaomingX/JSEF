// [SAFE]
// 安全对照：MVEL 表达式注入（修复版）
// 修复原则：避免使用用户输入作为表达式直接执行；如必须计算表达式，使用受信任的常量
//          表达式并彻底隔离用户输入。本示例拒绝执行用户提供的表达式。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：不执行任何用户提供的 MVEL 表达式，移除 MVEL.eval / executeExpression sink。
 */
@RestController
@RequestMapping("/benchmark/sec/mvel")
public class MvelInjectionSafe {

    /**
     * 安全示例：直接调用 MVEL.eval 的场景改为拒绝执行不可信输入。
     */
    @GetMapping("/safe/eval-direct")
    public String safeMvelDirectEval(@RequestParam String userInputExpression) {
        // 安全实践：用户输入不再流向 MVEL.eval。
        // [CHECKPOINT id=JSEF-MVEL-001S cwe=917 level=L1 source=@RequestParam userInputExpression sink=no MVEL.eval (input rejected) expect=SAFE]
        return "{\"status\":\"已拒绝执行不可信表达式（安全）\"}";
    }

    /**
     * 安全示例：预编译+执行 MVEL 表达式的场景改为拒绝执行不可信输入。
     */
    @GetMapping("/safe/eval-compiled")
    public String safeMvelCompiledEval(@RequestParam String userInputExpression) {
        // 安全实践：用户输入不再流向 MVEL.executeExpression。
        // [CHECKPOINT id=JSEF-MVEL-002S cwe=917 level=L1 source=@RequestParam userInputExpression sink=no MVEL.executeExpression (input rejected) expect=SAFE]
        return "{\"status\":\"已拒绝执行不可信表达式（安全）\"}";
    }
}
