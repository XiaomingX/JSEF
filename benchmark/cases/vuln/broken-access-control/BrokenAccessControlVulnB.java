// [VULN]
// 漏洞样本：访问控制失效——垂直越权修改他人角色（无权限校验）
// 漏洞点：允许任意用户修改任意用户角色，未验证操作者是否为管理员。
package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.*;

/**
 * 不安全示例：角色修改接口缺乏权限验证，存在垂直越权。
 */
@RestController
@RequestMapping("/benchmark/vuln/broken-access-control")
public class BrokenAccessControlVulnB {

    /**
     * 不安全示例：修改用户角色，未校验调用者权限。
     */
    @PostMapping("/unsafe/update-role")
    public String unsafeUpdateUserRole(@RequestParam Integer userId, @RequestParam String newRole) {
        // 危险实践：未验证操作者是否具有修改角色的权限
        // [CHECKPOINT id=JSEF-BROKENAC-002 cwe=285 level=L1 source=@RequestParam userId,newRole sink=role update (no privilege check) expect=VULN]
        return "Updated role to " + newRole + " for user: " + userId;
    }
}
