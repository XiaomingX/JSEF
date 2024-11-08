package com.freedom.securitysamples.api.authBypass;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AuthBypassController {

    @GetMapping("/admin/info")
    public String getAdminInfo(@RequestParam(required = false) String role) {
        // 不安全的角色验证方式
        if (role != null && role.equals("admin")) {
            return "{'status':'success','data':'这里是管理员敏感信息','role':'admin'}";
        }
        return "{'status':'error','msg':'权限不足'}";
    }

    // 另一个认证绕过的示例
    @GetMapping("/user/profile")
    public String getUserProfile(@RequestParam(required = false) Integer userId) {
        // 未进行proper身份验证就直接返回用户信息
        if (userId != null) {
            return "{'status':'success','data':'用户ID " + userId + " 的个人信息','sensitive':'银行卡号:6222***'}";
        }
        return "{'status':'error','msg':'用户不存在'}";
    }
}