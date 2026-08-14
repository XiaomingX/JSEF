// [SAFE]
// 安全对照：脚本引擎注入（修复版）
// 修复原则：避免执行用户提供的任何脚本内容；若必须使用，采用严格沙箱机制并禁用危险类。
//          本示例拒绝执行用户提供的脚本，移除 ScriptEngine.eval / CompiledScript.eval sink。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：不将用户输入交给脚本引擎执行。
 */
@RestController
@RequestMapping("/benchmark/sec/script-engine")
public class ScriptEngineInjectionSafe {

    /**
     * 安全示例：通过 ScriptEngineManager 执行脚本的场景改为拒绝执行不可信输入。
     */
    @GetMapping("/safe/engine-manager-exec")
    public String safeScriptExecutionByManager(@RequestParam String userControlledScript) {
        // 安全实践：用户输入不再流向 ScriptEngine.eval。
        // [CHECKPOINT id=JSEF-SCRIPT-001S cwe=917 level=L1 source=@RequestParam userControlledScript sink=no ScriptEngine.eval (input rejected) expect=SAFE]
        return "{\"status\":\"已拒绝执行不可信脚本（安全）\"}";
    }

    /**
     * 安全示例：编译并执行用户脚本的场景改为拒绝执行不可信输入。
     */
    @GetMapping("/safe/compiled-exec")
    public String safeCompiledScriptExecution(@RequestParam String userControlledScript) {
        // 安全实践：用户输入不再流向 CompiledScript.eval。
        // [CHECKPOINT id=JSEF-SCRIPT-002S cwe=917 level=L1 source=@RequestParam userControlledScript sink=no CompiledScript.eval (input rejected) expect=SAFE]
        return "{\"status\":\"已拒绝执行不可信脚本（安全）\"}";
    }
}
