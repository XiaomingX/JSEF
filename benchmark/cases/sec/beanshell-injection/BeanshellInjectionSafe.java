// [SAFE]
// 安全对照：BeanShell 脚本注入（修复版）
// 修复原则：严禁执行用户提供的任何脚本代码。若必须执行动态逻辑，使用受信任的固定脚本或
//          预定义白名单，绝不允许用户输入作为可执行脚本内容。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：不执行任何用户提供的脚本，仅返回受信任的静态处理结果。
 * 关键点：source（用户输入的脚本）不再流向脚本执行引擎（sink 已被移除）。
 */
@RestController
@RequestMapping("/benchmark/sec/beanshell")
public class BeanshellInjectionSafe {

    /**
     * 安全示例：拒绝执行用户提供的 BeanShell 脚本，改用受信任的常量结果。
     */
    @GetMapping("/safe/evaluate-beanshell")
    public String safeEvaluateBeanshellScript(@RequestParam String userProvidedScript) {
        // 安全实践：不将用户输入交给任何脚本引擎；此处仅做受信任处理。
        // [CHECKPOINT id=JSEF-BEANSHELL-001S cwe=917 level=L1 source=@RequestParam userProvidedScript sink=no script engine invocation (input rejected) expect=SAFE]
        if (userProvidedScript == null || userProvidedScript.isEmpty()) {
            return "{\"message\": \"缺少脚本输入\"}";
        }
        return "{\"message\": \"已拒绝执行不可信脚本（安全）\"}";
    }

    /**
     * 安全示例：不执行用户提供的系统命令，直接拒绝。
     */
    @GetMapping("/safe/execute-system-command")
    public String safeExecuteSystemCommand(@RequestParam String userCommand) {
        // 安全实践：用户输入的命令永不被执行。
        // [CHECKPOINT id=JSEF-BEANSHELL-002S cwe=917 level=L1 source=@RequestParam userCommand sink=no Runtime.exec (input rejected) expect=SAFE]
        return "{\"message\": \"已拒绝执行不可信命令（安全）\"}";
    }
}
