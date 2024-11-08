package com.freedom.securitysamples.api.spelInjection;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import jakarta.el.ELProcessor;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SpelController {
    private static final ExpressionParser expressionParser = new SpelExpressionParser();

    @GetMapping("/spel/bad01")
    public String executeSpel01(String userInput) {
        SpelExpressionParser spelParser = new SpelExpressionParser();
        Expression parsedExpression = spelParser.parseExpression(userInput);
        String result = (String) parsedExpression.getValue();
        return "success";
    }

    @GetMapping("/spel/bad02")
    public String executeSpel02(String userInput) {
        SpelExpressionParser spelParser = new SpelExpressionParser();
        SpelExpression parsedExpression = spelParser.parseRaw(userInput);
        parsedExpression.getValue();
        return "success";
    }

    @GetMapping("/spel/bad03")
    public String executeSpel03(String userInput) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression parsedExpression = parser.parseExpression(userInput);
        parsedExpression.getValue(); // $hasSpelInjection
        return "success";
    }

    @GetMapping("/spel/bad04")
    public String executeSpel04(String userInput) {
        Expression parsedExpression = new SpelExpressionParser().parseExpression(userInput);
        parsedExpression.getValue(); // $hasSpelInjection
        return "success";
    }

    @GetMapping("/spel/bad05")
    public String executeSpel05(String userInput) {
        Expression parsedExpression = new SpelExpressionParser().parseExpression(userInput);

        Object targetObject = new Object();
        Object newValue = new Object();
        parsedExpression.setValue(targetObject, newValue); // $hasSpelInjection
        return "success";
    }

    @GetMapping("/spel/bad06")
    public String executeSpel06(String userInput) {
        Expression parsedExpression = expressionParser.parseExpression(userInput);
        parsedExpression.getValue(); // $hasSpelInjection
        return "success";
    }

    @GetMapping("/spel/bad07")
    public String executeSpel07(String userInput) {
        Expression parsedExpression = expressionParser.parseExpression(userInput);
        parsedExpression.getValueType(); // $hasSpelInjection
        return "success";
    }

    @GetMapping("/spel/bad08")
    public String executeSpel08(String userInput) {
        Expression parsedExpression = expressionParser.parseExpression(userInput);

        StandardEvaluationContext evaluationContext = new StandardEvaluationContext();
        parsedExpression.getValue(evaluationContext); // $hasSpelInjection
        return "success";
    }

    @GetMapping("/spel/bad10")
    public String executeSpel10(String userInput) {
        // 在变量赋值中使用不受信任的输入
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("input", userInput);
        Expression parsedExpression = expressionParser.parseExpression("#input");
        return parsedExpression.getValue(context).toString(); // 危险
    }

    @GetMapping("/spel/bad11")
    public String executeSpel11(String userInput) {
        // 在方法调用中使用不受信任的输入
        Map<String, Object> contextMap = new HashMap<>();
        contextMap.put("cmd", userInput);
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setRootObject(contextMap);
        Expression parsedExpression = expressionParser.parseExpression("cmd.toString()");
        return parsedExpression.getValue(context).toString(); // 危险
    }

    @GetMapping("/el-dangerous-example")
    public String elDangerousExample(@RequestParam String userInput) {
        ELProcessor elProcessor = new ELProcessor();
        String result;
        try {
            result = (String) elProcessor.eval(userInput);
        } catch (Exception e) {
            result = "Error evaluating expression: " + e.getMessage();
        }
        return "EL Dangerous example result: " + result;
    }

    @GetMapping("/spel/bad12")
    public String executeSpel12(String userInput) {
        // 在类型转换中使用不受信任的输入
        Expression parsedExpression = expressionParser.parseExpression("T(" + userInput + ")");
        return parsedExpression.getValue().toString(); // 危险
    }

    @GetMapping("/spel/bad13")
    public String executeSpel13(String userInput) {
        // 在属性访问中使用不受信任的输入
        StandardEvaluationContext context = new StandardEvaluationContext();
        Expression parsedExpression = expressionParser.parseExpression("@systemProperties['" + userInput + "']");
        return parsedExpression.getValue(context).toString(); // 危险
    }

    @GetMapping("/spel/bad14")
    public String executeSpel14(String userInput) {
        // 在列表操作中使用不受信任的输入
        Expression parsedExpression = expressionParser.parseExpression("{" + userInput + "}");
        return parsedExpression.getValue().toString(); // 危险
    }

    @GetMapping("/spel/bad15")
    public String executeSpel15(String userInput) {
        // 在运算符中使用不受信任的输入
        Expression parsedExpression = expressionParser.parseExpression("2 " + userInput + " 2");
        return parsedExpression.getValue().toString(); // 危险
    }

    // 安全的实现示例
    @GetMapping("/spel/good02")
    public String safeSpel01(String userInput) {
        // 使用白名单验证输入
        if(!isValidExpression(userInput)) {
            return "Invalid input";
        }
        SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        Expression parsedExpression = expressionParser.parseExpression(userInput);
        return parsedExpression.getValue(context).toString();
    }

    @GetMapping("/spel/good03")
    public String safeSpel02(String userInput) {
        // 使用参数化表达式
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("safeInput", userInput);
        Expression parsedExpression = expressionParser.parseExpression("#safeInput?.toString()");
        return parsedExpression.getValue(context).toString();
    }

    private boolean isValidExpression(String input) {
        // 实现表达式白名单验证逻辑
        String[] allowedExpressions = {"true", "false", "null", "empty"};
        for(String allowed : allowedExpressions) {
            if(allowed.equals(input)) {
                return true;
            }
        }
        return false;
    }
    @GetMapping("/spel/good01")
    public String executeSpel09(String userInput) {
        Expression parsedExpression = expressionParser.parseExpression(userInput);
        SimpleEvaluationContext evaluationContext = SimpleEvaluationContext.forReadWriteDataBinding().build();

        parsedExpression.getValue(evaluationContext); // Safe - the expression is evaluated in a limited context
        return "success";
    }
}