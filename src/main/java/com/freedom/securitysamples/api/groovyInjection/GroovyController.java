package com.freedom.securitysamples.api.groovyInjection;

import groovy.lang.*;
import groovy.util.Eval;
import groovy.util.GroovyScriptEngine;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.springframework.scripting.ScriptSource;
import org.springframework.scripting.groovy.GroovyScriptEvaluator;
import org.springframework.scripting.support.StaticScriptSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.io.File;
import java.io.StringReader;

@RestController
@RequestMapping("/api")
public class GroovyController {

    // 原有的5个危险示例保持不变
    @GetMapping("/groovy/bad01")
    public String executeGroovyScriptWithEvaluator(String groovyScript) {
        GroovyScriptEvaluator scriptEvaluator = new GroovyScriptEvaluator();
        ScriptSource scriptSource = new StaticScriptSource(groovyScript);
        scriptEvaluator.evaluate(scriptSource);
        return "{'msg':'false'}";
    }

    @GetMapping("/groovy/bad02")
    public String executeGroovyScriptWithClassLoader(String groovyScript) throws InstantiationException, IllegalAccessException {
        final GroovyClassLoader groovyClassLoader = new GroovyClassLoader();
        Class<?> parsedClass = groovyClassLoader.parseClass(groovyScript);
        GroovyObject groovyObject = (GroovyObject) parsedClass.newInstance();
        return "{'msg':'false'}";
    }

    @GetMapping("/groovy/bad03")
    public String executeGroovyScriptWithEval(String groovyScript){
        Eval.me(groovyScript);
        return "{'msg':'false'}";
    }

    @GetMapping("/groovy/bad04")
    public String executeGroovyScriptWithShell(String groovyScript){
        GroovyShell groovyShell = new GroovyShell();
        groovyShell.evaluate(groovyScript);
        return "{'msg':'false'}";
    }

    @GetMapping("/groovy/bad05")
    public String executeGroovyScriptWithCodeSource(String groovyScript){
        GroovyShell groovyShell = new GroovyShell();
        GroovyCodeSource codeSource = new GroovyCodeSource(groovyScript, "test", "Test");
        groovyShell.evaluate(codeSource);
        return "{'msg':'false'}";
    }

    // 新增危险示例
    @GetMapping("/groovy/bad06")
    public String executeGroovyScriptWithBinding(String groovyScript) {
        // 使用Binding传递变量的方式执行脚本(危险)
        Binding binding = new Binding();
        binding.setVariable("input", groovyScript);
        GroovyShell shell = new GroovyShell(binding);
        shell.evaluate("println input");
        return "{'msg':'false'}";
    }

    @GetMapping("/groovy/bad07")
    public String executeGroovyScriptWithScriptEngine(String groovyScript) throws Exception {
        // 使用javax.script.ScriptEngine执行Groovy脚本(危险)
        ScriptEngineManager factory = new ScriptEngineManager();
        ScriptEngine engine = factory.getEngineByName("groovy");
        engine.eval(new StringReader(groovyScript));
        return "{'msg':'false'}";
    }

    @GetMapping("/groovy/bad08")
    public String executeGroovyScriptWithCustomConfig(String groovyScript) {
        // 使用自定义编译配置执行脚本(危险)
        CompilerConfiguration config = new CompilerConfiguration();
        GroovyShell shell = new GroovyShell(config);
        shell.evaluate(groovyScript);
        return "{'msg':'false'}";
    }

    @GetMapping("/groovy/bad09")
    public String executeGroovyScriptFromFile(String filePath) throws Exception {
        // 从文件加载并执行Groovy脚本(危险)
        GroovyScriptEngine engine = new GroovyScriptEngine(new String[]{filePath});
        engine.run(new File(filePath).getName(), "");
        return "{'msg':'false'}";
    }

    @GetMapping("/groovy/bad10")
    public String executeGroovyScriptWithBaseScript(String groovyScript) {
        // 使用BaseScript注解执行脚本(危险)
        CompilerConfiguration config = new CompilerConfiguration();
        config.setScriptBaseClass("groovy.lang.Script");
        GroovyShell shell = new GroovyShell(config);
        shell.evaluate(groovyScript);
        return "{'msg':'false'}";
    }
}