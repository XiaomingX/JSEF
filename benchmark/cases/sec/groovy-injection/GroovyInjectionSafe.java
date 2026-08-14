// [SAFE]
// 安全对照：Groovy 代码注入（修复版）
// 修复原则：避免执行任何来自不可信来源的脚本代码；如必须使用，实施严格的输入验证、
//          白名单机制与最小权限沙箱。本示例直接拒绝执行不可信脚本。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：不将用户输入作为 Groovy 脚本执行，移除所有脚本执行 sink。
 */
@RestController
@RequestMapping("/benchmark/sec/groovy")
public class GroovyInjectionSafe {

    /**
     * 安全示例：使用 GroovyScriptEvaluator 的场景改为拒绝执行不可信输入。
     */
    @GetMapping("/safe/evaluator")
    public String safeScriptWithEvaluator(@RequestParam String groovyScript) {
        // 安全实践：用户输入不再流向 GroovyScriptEvaluator.evaluate。
        // [CHECKPOINT id=JSEF-GROOVY-001S cwe=917 level=L1 source=@RequestParam groovyScript sink=no script evaluation (input rejected) expect=SAFE]
        return "{\"message\":\"已拒绝执行不可信 Groovy 脚本（安全）\"}";
    }

    /**
     * 安全示例：使用 GroovyShell 的场景改为拒绝执行不可信输入。
     */
    @GetMapping("/safe/shell")
    public String safeScriptWithShell(@RequestParam String groovyScript) {
        // 安全实践：用户输入不再流向 GroovyShell.evaluate。
        // [CHECKPOINT id=JSEF-GROOVY-002S cwe=917 level=L1 source=@RequestParam groovyScript sink=no shell evaluation (input rejected) expect=SAFE]
        return "{\"message\":\"已拒绝执行不可信 Groovy 脚本（安全）\"}";
    }
}
