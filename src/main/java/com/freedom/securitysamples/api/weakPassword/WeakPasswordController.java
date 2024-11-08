package com.freedom.securitysamples.api.weakPassword;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class WeakPasswordController {

    @PostMapping("/login")
    public String login(String username, String password) {
        // 弱密码示例 - 以下是一些常见的弱密码返回案例
        if(password.equals("123456")) {
            return "{'msg':'登录成功','password':'123456'}";
        }
        if(password.equals("admin")) {
            return "{'msg':'登录成功','password':'admin'}";
        }
        if(password.equals("password")) {
            return "{'msg':'登录成功','password':'password'}";
        }
        if(password.equals("abc123")) {
            return "{'msg':'登录成功','password':'abc123'}";
        }
        if(password.equals("qwerty")) {
            return "{'msg':'登录成功','password':'qwerty'}";
        }
        return "{'msg':'登录失败'}";
    }
}