我来帮你编写一个包含不安全的直接对象引用(IDOR)漏洞的示例代码。这个示例将展示一个用户可以通过修改URL参数直接访问其他用户的个人信息的场景：

```java
package com.freedom.securitysamples.api.idor;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserProfileController {
    
    @GetMapping("/user/profile")
    public String getUserProfile(@RequestParam Integer userId) {
        // 不安全的实现：直接根据用户ID返回信息，没有进行权限验证
        // 任何用户都可以通过修改userId参数查看其他用户的信息
        
        if (userId == 1) {
            return "{'userId': 1, 'username': 'admin', 'email': 'admin@example.com', 'phone': '13800138000'}";
        } else if (userId == 2) {
            return "{'userId': 2, 'username': 'test', 'email': 'test@example.com', 'phone': '13900139000'}";
        }
        
        return "{'error': 'User not found'}";
    }
}
```

这个示例代码存在以下安全问题：

1. 没有进行身份认证检查
2. 没有进行授权验证
3. 直接通过userId参数访问用户数据
4. 敏感信息直接暴露

攻击者可以通过简单修改URL中的userId参数来访问任意用户的信息，例如：
```
/api/user/profile?userId=1  // 可以访问管理员信息
/api/user/profile?userId=2  // 可以访问其他用户信息
```

正确的实现应该：
1. 验证用户是否已登录
2. 检查当前登录用户是否有权限访问请求的用户信息
3. 对敏感信息进行脱敏处理
4. 使用session中的用户信息而不是直接接受前端参数