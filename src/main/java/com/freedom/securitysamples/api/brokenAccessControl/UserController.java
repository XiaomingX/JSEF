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