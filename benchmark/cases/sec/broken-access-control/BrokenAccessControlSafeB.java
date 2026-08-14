// [SAFE]
// 安全对照：垂直越权角色修改（修复版）
// 修复原则：修改角色前校验操作者管理员权限。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：角色修改接口校验管理员权限。
 */
@RestController
@RequestMapping("/benchmark/sec/broken-access-control")
public class BrokenAccessControlSafeB {

    /**
     * 安全示例：仅管理员可修改角色。
     */
    @PostMapping("/safe/update-role")
    public String safeUpdateUserRole(@RequestParam Integer userId, @RequestParam String newRole) {
        String currentLoginUserId = getCurrentLoginUserId();
        if (currentLoginUserId == null) {
            return "{'error':'请先登录'}";
        }
        // 安全实践：管理员权限校验
        // [CHECKPOINT id=JSEF-BROKENAC-003S cwe=285 level=L1 source=@RequestParam userId,newRole sink=admin role check before role update expect=SAFE]
        if (!isAdmin(currentLoginUserId)) {
            return "{'error':'权限不足：仅管理员可修改角色'}";
        }
        return "Updated role to " + newRole + " for user: " + userId;
    }

    private String getCurrentLoginUserId() {
        return "1001";
    }

    private boolean isAdmin(String userId) {
        return "1001".equals(userId);
    }
}
