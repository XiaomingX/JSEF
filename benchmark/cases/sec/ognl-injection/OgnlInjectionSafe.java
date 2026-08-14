// [SAFE]
// 安全对照：OGNL 表达式注入（修复版）
// 修复原则：严禁使用用户输入直接拼接或作为 OGNL 表达式执行；采用严格白名单与沙箱。
//          本示例拒绝执行用户提供的 OGNL 表达式。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：不将用户输入作为 OGNL 表达式解析执行，移除 Ognl.getValue sink。
 */
@RestController
@RequestMapping("/benchmark/sec/ognl")
public class OgnlInjectionSafe {

    /**
     * 安全示例：直接执行用户 OGNL 表达式的场景改为拒绝执行不可信输入。
     */
    @GetMapping("/safe/evaluate-raw")
    public String safeEvaluateRawOgnl(@RequestParam String userControlledOgnlExpression) {
        // 安全实践：用户输入不再流向 Ognl.getValue/parseExpression。
        // [CHECKPOINT id=JSEF-OGNL-001S cwe=917 level=L1 source=@RequestParam userControlledOgnlExpression sink=no Ognl.getValue (input rejected) expect=SAFE]
        return "{\"status\":\"已拒绝执行不可信 OGNL 表达式（安全）\"}";
    }

    /**
     * 安全示例：拼接用户输入执行系统命令的场景改为拒绝执行不可信输入。
     */
    @GetMapping("/safe/exec-command")
    public String safeExecuteSystemCommand(@RequestParam String userInputCommand) {
        // 安全实践：用户输入不再拼接为 Ognl.getValue(Runtime.exec) 表达式。
        // [CHECKPOINT id=JSEF-OGNL-002S cwe=917 level=L2 source=@RequestParam userInputCommand sink=no Ognl.getValue(Runtime.exec) (input rejected) expect=SAFE]
        return "{\"status\":\"已拒绝构造不可信命令表达式（安全）\"}";
    }
}
