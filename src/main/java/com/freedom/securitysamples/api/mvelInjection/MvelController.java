package com.freedom.securitysamples.api.mvelInjection;

import cn.hutool.extra.expression.engine.mvel.MvelEngine;
import ognl.OgnlException;
import org.mvel2.MVEL;
import org.mvel2.integration.impl.MapVariableResolverFactory;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class MvelController {

    // 原有的不安全示例1
    @GetMapping("/mvel/bad01")
    public String executeMvelWithPayload(String mvelPayload) throws OgnlException {
        MvelEngine mvelEngine = new MvelEngine();
        mvelEngine.eval(mvelPayload, null);
        return "{'msg':'false'}";
    }

    // 原有的不安全示例2
    @GetMapping("/mvel/bad02")
    public String executeMvelDirectly(String mvelPayload) throws OgnlException {
        MVEL.eval(mvelPayload);
        return "{'msg':'false'}";
    }

    // 新增不安全示例3：使用编译后的表达式
    @GetMapping("/mvel/bad03")
    public String executeCompiledMvel(String mvelPayload) {
        Serializable compiled = MVEL.compileExpression(mvelPayload);
        MVEL.executeExpression(compiled);
        return "{'msg':'false'}";
    }

    // 新增不安全示例4：带变量的MVEL执行
    @PostMapping("/mvel/bad04")
    public String executeMvelWithVariables(@RequestBody Map<String, Object> input) {
        String expression = (String) input.get("expression");
        Map<String, Object> vars = (Map<String, Object>) input.get("variables");
        MVEL.eval(expression, vars);
        return "{'msg':'false'}";
    }

    // 新增不安全示例5：使用MapVariableResolverFactory
    @GetMapping("/mvel/bad05")
    public String executeMvelWithResolver(String mvelPayload) {
        Map<String, Object> vars = new HashMap<>();
        MapVariableResolverFactory factory = new MapVariableResolverFactory(vars);
        MVEL.eval(mvelPayload, factory);
        return "{'msg':'false'}";
    }

    // 新增不安全示例6：模板解析
    @GetMapping("/mvel/bad06")
    public String executeMvelTemplate(String template) {
        org.mvel2.templates.TemplateRuntime.eval(template, new HashMap());
        return "{'msg':'false'}";
    }

    // 新增不安全示例7：动态方法调用
    @GetMapping("/mvel/bad07")
    public String executeMvelMethod(String className, String methodName) {
        String payload = className + "." + methodName + "()";
        MVEL.eval(payload);
        return "{'msg':'false'}";
    }

    // 新增不安全示例8：条件表达式执行
    @GetMapping("/mvel/bad08")
    public String executeMvelCondition(String condition) {
        String payload = "if (" + condition + ") { Runtime.getRuntime().exec('calc.exe'); }";
        MVEL.eval(payload);
        return "{'msg':'false'}";
    }
}