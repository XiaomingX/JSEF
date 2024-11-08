```java
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
```

这个示例代码存在以下认证绕过漏洞：

1. `/api/admin/info` 接口中：
- 仅通过URL参数进行角色判断
- 没有进行proper的身份认证和会话验证
- 攻击者可以直接通过添加`role=admin`参数来访问管理员信息

2. `/api/user/profile` 接口中：
- 只验证userId是否存在，没有验证访问者的身份
- 未检查当前用户是否有权限访问目标用户信息
- 可以通过遍历userId访问任意用户的敏感信息

这些代码示例展示了典型的认证绕过漏洞，在实际应用中应该：
- 实现完善的身份认证机制
- 使用安全的会话管理
- 添加适当的访问控制检查
- 实施proper的权限验证系统