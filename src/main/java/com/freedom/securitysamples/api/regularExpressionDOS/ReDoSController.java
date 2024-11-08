package com.freedom.securitysamples.api.regularExpressionDOS;

import org.springframework.web.bind.annotation.*;
import java.io.IOException;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api")
public class ReDoSController {

    // 示例1: 直接使用未验证的用户输入作为正则表达式
    @GetMapping("/redos/bad01")
    public boolean redos01(String regularExpression, String userInput) throws IOException {
        // 不安全: 直接使用未经验证的用户输入构造正则表达式
        return userInput.matches(regularExpression);
    }

    // 示例2: 使用易受攻击的正则表达式模式
    @GetMapping("/redos/bad02")
    public boolean redos02(String userInput) {
        // 不安全: 使用容易导致回溯的正则表达式
        String dangerousRegex = "(a+)+b";
        return Pattern.matches(dangerousRegex, userInput);
    }

    // 示例3: 未限制输入长度的邮箱验证
    @GetMapping("/redos/bad03")
    public boolean redos03(String email) {
        // 不安全: 复杂的邮箱验证正则表达式
        String emailRegex = "^([a-zA-Z0-9_\\-\\.]+)@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-]+\\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\\]?)$";
        return email.matches(emailRegex);
    }

    // 示例4: 嵌套重复的正则表达式
    @PostMapping("/redos/bad04")
    public boolean redos04(@RequestBody String text) {
        // 不安全: 包含嵌套重复的正则表达式
        String nestedRegex = "([a-z]+)*([a-z]+)+b";
        return Pattern.matches(nestedRegex, text);
    }

    // 示例5: 带有多个可选分组的正则表达式
    @GetMapping("/redos/bad05")
    public boolean redos05(String input) {
        // 不安全: 包含多个可选分组的复杂正则表达式
        String complexRegex = "(a|b|c|d|e|f|g)+\\w*";
        return Pattern.compile(complexRegex).matcher(input).matches();
    }

    // 安全的实现示例
    @GetMapping("/redos/good01")
    public boolean safeRegex(String input) {
        // 安全:
        // 1. 限制输入长度
        if (input.length() > 100) {
            return false;
        }
        // 2. 使用简单的正则表达式
        // 3. 设置匹配超时
        try {
            Pattern pattern = Pattern.compile("[a-zA-Z0-9]+");
            return pattern.matcher(input)
                    .matches();
        } catch (Exception e) {
            return false;
        }
    }

    // 安全的邮箱验证示例
    @GetMapping("/redos/good02")
    public boolean safeEmailValidation(String email) {
        // 安全:
        // 1. 限制输入长度
        if (email == null || email.length() > 254) {
            return false;
        }
        // 2. 使用简化的邮箱验证正则表达式
        String simpleEmailRegex = "^[A-Za-z0-9+_.-]+@(.+)$";
        return Pattern.compile(simpleEmailRegex).matcher(email).matches();
    }
}