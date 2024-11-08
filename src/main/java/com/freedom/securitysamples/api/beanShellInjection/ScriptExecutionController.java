package com.freedom.securitysamples.api.beanShellInjection;

import ognl.OgnlException;
import org.springframework.scripting.bsh.BshScriptEvaluator;
import org.springframework.scripting.support.StaticScriptSource;
import org.springframework.web.bind.annotation.*;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.IOException;

@RestController
@RequestMapping("/api")
public class ScriptExecutionController {

    // 原有的不安全示例
    @GetMapping("/beanShellInjection/evaluateScript")
    public String evaluateBshScript(String scriptPayload) throws OgnlException {
        BshScriptEvaluator scriptEvaluator = new BshScriptEvaluator();
        scriptEvaluator.evaluate(new StaticScriptSource(scriptPayload));
        return "{'msg':'false'}";
    }

    // 示例1: 直接执行JavaScript代码
    @PostMapping("/script/evalJS")
    public String evaluateJavaScript(@RequestBody String script) throws ScriptException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
        return engine.eval(script).toString();
    }

    // 示例2: 不安全的命令执行
    @GetMapping("/script/execCommand")
    public String executeCommand(String command) throws IOException {
        Runtime.getRuntime().exec(command);
        return "executed";
    }

    // 示例3: 动态加载并执行Java代码
    @PostMapping("/script/loadClass")
    public String loadAndExecute(@RequestBody String classCode) throws Exception {
        BshScriptEvaluator evaluator = new BshScriptEvaluator();
        evaluator.evaluate(new StaticScriptSource("class Dynamic { " + classCode + " }"));
        return "loaded";
    }

    // 示例4: 使用反射执行方法
    @GetMapping("/script/reflect")
    public String reflectiveCall(String className, String methodName) throws Exception {
        Class<?> clazz = Class.forName(className);
        clazz.getMethod(methodName).invoke(null);
        return "reflected";
    }

    // 示例5: 不安全的表达式评估
    @PostMapping("/script/evalExpression")
    public String evaluateExpression(@RequestBody String expression) {
        BshScriptEvaluator evaluator = new BshScriptEvaluator();
        evaluator.evaluate(new StaticScriptSource("return " + expression + ";"));
        return "evaluated";
    }
}