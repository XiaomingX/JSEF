package com.freedom.securitysamples.api.scriptEngineInjection;

import org.openjdk.nashorn.api.scripting.NashornScriptEngine;
import org.openjdk.nashorn.api.scripting.NashornScriptEngineFactory;
import org.springframework.web.bind.annotation.*;
import javax.script.*;
import java.io.FileReader;
import java.io.StringReader;

@RestController
@RequestMapping("/api")
public class ScriptEngineController {

    // 原有的不安全示例1
    @GetMapping("/scriptengine/execute01")
    public String executeScriptWithEngineManager(String scriptPayload) throws ScriptException {
        ScriptEngineManager scriptEngineManager = new ScriptEngineManager();
        ScriptEngine nashornScriptEngine = scriptEngineManager.getEngineByName("nashorn");
        nashornScriptEngine.eval(scriptPayload);
        return "success";
    }

    // 原有的不安全示例2
    @GetMapping("/scriptengine/execute02")
    public String executeScriptWithEngineFactory(String scriptPayload) throws ScriptException {
        NashornScriptEngineFactory scriptEngineFactory = new NashornScriptEngineFactory();
        NashornScriptEngine nashornScriptEngine = (NashornScriptEngine) scriptEngineFactory.getScriptEngine(new String[]{"-scripting"});
        Object scriptResult = nashornScriptEngine.eval(scriptPayload);
        return "success";
    }

    // 新增不安全示例3：从文件读取脚本执行
    @GetMapping("/scriptengine/execute03")
    public String executeScriptFromFile(String filePath) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        engine.eval(new FileReader(filePath));  // 不安全：允许任意文件读取
        return "success";
    }

    // 新增不安全示例4：绑定变量执行
    @GetMapping("/scriptengine/execute04")
    public String executeScriptWithBinding(String scriptPayload) throws ScriptException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        Bindings bindings = engine.createBindings();
        bindings.put("system", System.class);  // 不安全：暴露系统类
        engine.eval(scriptPayload, bindings);
        return "success";
    }

    // 新增不安全示例5：使用compile方法
    @GetMapping("/scriptengine/execute05")
    public String executeCompiledScript(String scriptPayload) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        Compilable compilable = (Compilable) engine;
        CompiledScript compiled = compilable.compile(scriptPayload);  // 不安全：编译任意脚本
        compiled.eval();
        return "success";
    }

    // 新增不安全示例6：使用Invocable接口
    @GetMapping("/scriptengine/execute06")
    public String executeScriptFunction(String scriptPayload, String functionName) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        engine.eval(scriptPayload);
        Invocable invocable = (Invocable) engine;
        invocable.invokeFunction(functionName);  // 不安全：调用任意函数
        return "success";
    }

    // 新增不安全示例7：多引擎组合使用
    @GetMapping("/scriptengine/execute07")
    public String executeMultipleEngines(String scriptPayload) throws Exception {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine jsEngine = manager.getEngineByName("nashorn");
        ScriptEngine pythonEngine = manager.getEngineByName("python");

        jsEngine.eval(scriptPayload);  // 不安全：多引擎组合可能导致更复杂的攻击
        if(pythonEngine != null) {
            pythonEngine.eval(scriptPayload);
        }
        return "success";
    }

    // 新增不安全示例8：使用StringReader
    @GetMapping("/scriptengine/execute08")
    public String executeScriptFromReader(String scriptPayload) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        StringReader reader = new StringReader(scriptPayload);
        engine.eval(reader);  // 不安全：通过Reader执行任意脚本
        return "success";
    }
}