package com.freedom.securitysamples.api.onglInjection;

import ognl.Ognl;
import ognl.OgnlException;
import org.springframework.web.bind.annotation.*;
import java.io.File;

@RestController
@RequestMapping("/api")
public class OgnlController {

    // 原有的不安全示例
    @GetMapping("/ognl/evaluate")
    public String evaluateOgnlExpression(String ognlExpression) throws OgnlException {
        Ognl.getValue(Ognl.parseExpression(ognlExpression), null);
        return "{'msg':'false'}";
    }

    // 示例1: 直接执行系统命令
    @GetMapping("/ognl/command")
    public String executeCommand(String cmd) throws OgnlException {
        String exp = "@java.lang.Runtime@getRuntime().exec('" + cmd + "')";
        Ognl.getValue(Ognl.parseExpression(exp), null);
        return "executed";
    }

    // 示例2: 文件操作
    @PostMapping("/ognl/file")
    public String fileOperation(String path) throws OgnlException {
        String exp = "new java.io.File('" + path + "').delete()";
        Ognl.getValue(Ognl.parseExpression(exp), null);
        return "file operated";
    }

    // 示例3: 反射调用
    @GetMapping("/ognl/reflect")
    public String reflectCall(String className, String methodName) throws OgnlException {
        String exp = "@" + className + "@" + methodName + "()";
        Ognl.getValue(Ognl.parseExpression(exp), null);
        return "reflected";
    }

    // 示例4: 不安全的对象实例化
    @GetMapping("/ognl/create")
    public String createObject(String className) throws OgnlException {
        String exp = "new " + className + "()";
        Ognl.getValue(Ognl.parseExpression(exp), null);
        return "object created";
    }

    // 示例5: 危险的静态方法调用
    @GetMapping("/ognl/static")
    public String callStatic(String expression) throws OgnlException {
        String exp = "@java.lang.System@" + expression;
        Ognl.getValue(Ognl.parseExpression(exp), null);
        return "static called";
    }
}