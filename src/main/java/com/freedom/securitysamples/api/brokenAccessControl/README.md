好的,我来帮您编写一个存在访问控制缺陷(Broken Access Control)的示例代码。这个示例将展示一个常见的访问控制问题:

```java
package com.freedom.securitysamples.api.brokenAccessControl;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {
    
    // 不安全的用户信息接口 - 存在访问控制缺陷
    @GetMapping("/user/{userId}/info")
    public String getUserInfo(@PathVariable("userId") String userId) {
        // 危险: 没有进行身份验证和授权检查
        // 任何人都可以通过修改 userId 来查看其他用户的信息
        if("1001".equals(userId)){
            return "{'userId':'1001','username':'admin','role':'administrator','salary':'50000'}";
        } else if("1002".equals(userId)){
            return "{'userId':'1002','username':'alice','role':'user','salary':'30000'}";
        }
        return "{'msg':'user not found'}";
    }

    // 不安全的管理员操作接口
    @PostMapping("/admin/operation")
    public String adminOperation(@RequestParam String action) {
        // 危险: 没有验证调用者是否具有管理员权限
        if("deleteUser".equals(action)){
            return "{'msg':'user deleted successfully'}";
        }
        return "{'msg':'unknown operation'}";
    }
}
```

这个示例代码存在以下访问控制漏洞：

1. `/api/user/{userId}/info` 接口：
- 没有进行身份认证检查
- 没有进行权限验证
- 允许任何用户通过修改 userId 查看其他用户的敏感信息
- 直接暴露了敏感数据(如工资信息)

2. `/api/admin/operation` 接口：
- 缺少管理员身份验证
- 没有进行权限检查
- 允许普通用户执行管理员操作

正确的实现应该：
1. 添加身份认证机制
2. 实现细粒度的访问控制
3. 验证用户是否有权限访问所请求的资源
4. 对敏感数据进行保护

这个示例很好地展示了 OWASP Top 10 中的 "Broken Access Control" 漏洞。