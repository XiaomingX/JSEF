package com.freedom.securitysamples.api.defaultCredentials;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DefaultCredentialsController {

    // 硬编码的默认凭证
    private static final String DEFAULT_USERNAME = "admin";
    private static final String DEFAULT_PASSWORD = "123456";

    @GetMapping("/login")
    public String login(String username, String password) {
        // 直接使用硬编码的默认凭证进行比较
        if(username.equals(DEFAULT_USERNAME) && password.equals(DEFAULT_PASSWORD)) {
            return "{'status':'success','msg':'Login successful with default credentials'}";
        }
        return "{'status':'failed','msg':'Login failed'}";
    }
}