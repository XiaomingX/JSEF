// [SAFE]
// 安全对照：访问控制失效（修复版）
// 修复原则：每个敏感操作前验证用户身份与资源所有权；水平越权（只能访问自己的数据）、
//          垂直越权（仅管理员可执行管理操作）均被拦截。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：用户信息与管理员操作均经过权限校验。
 */
@RestController
@RequestMapping("/benchmark/sec/broken-access-control")
public class BrokenAccessControlSafe {

    /**
     * 安全示例：水平越权防护——仅允许访问当前登录用户自己的信息。
     */
    @GetMapping("/safe/user/{userId}/info")
    public String safeGetUserInfo(@PathVariable("userId") String userId) {
        String currentLoginUserId = getCurrentLoginUserId();
        if (currentLoginUserId == null) {
            return "{'error':'请先登录'}";
        }
        // 安全实践：资源所有权校验，阻止水平越权
        // [CHECKPOINT id=JSEF-BROKENAC-001S cwe=285 level=L1 source=@PathVariable userId sink=owner check before return (access control enforced) expect=SAFE]
        if (!currentLoginUserId.equals(userId)) {
            return "{'error':'权限不足：您只能访问自己的信息'}";
        }
        return "{'userId':'" + userId + "','username':'alice','role':'user'}";
    }

    /**
     * 安全示例：垂直越权防护——仅管理员可执行管理操作。
     */
    @PostMapping("/safe/admin/operation")
    public String safeAdminOperation(@RequestParam String action) {
        String currentLoginUserId = getCurrentLoginUserId();
        if (currentLoginUserId == null) {
            return "{'error':'请先登录'}";
        }
        // 安全实践：角色权限校验，阻止垂直越权
        // [CHECKPOINT id=JSEF-BROKENAC-002S cwe=285 level=L1 source=@RequestParam action sink=admin role check before action (access control enforced) expect=SAFE]
        if (!isAdmin(currentLoginUserId)) {
            return "{'error':'权限不足：仅管理员可执行此操作'}";
        }
        return "{'msg':'operation done'}";
    }

    private String getCurrentLoginUserId() {
        return "1002";
    }

    private boolean isAdmin(String userId) {
        return "1001".equals(userId);
    }
}
