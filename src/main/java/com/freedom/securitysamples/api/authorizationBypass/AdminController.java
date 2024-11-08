package com.freedom.securitysamples.api.authorizationBypass;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/getUserInfo/{userId}")
    public String getUserInfo(@PathVariable String userId) {
        // 危险：直接返回用户信息，没有进行权限校验
        return "{'userId':'" + userId + "','username':'admin','role':'administrator','salary':'50000'}";
    }

    @GetMapping("/getAllUsers")
    public String getAllUsers() {
        // 危险：直接返回所有用户信息，没有进行权限校验
        return "{'users':[{'id':'1','username':'admin'},{'id':'2','username':'user'}]}";
    }

    @PostMapping("/updateUserRole/{userId}")
    public String updateUserRole(@PathVariable String userId, @RequestParam String newRole) {
        // 危险：直接修改用户角色，没有进行权限校验
        return "{'status':'success','message':'Role updated to " + newRole + "'}";
    }
}