// [SAFE]
// 安全对照：不安全直接对象引用（IDOR，修复版）
// 修复原则：验证当前登录用户是否为目标资源所有者；跨用户访问需管理员权限。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：用户资料查询前进行所有权校验。
 */
@RestController
@RequestMapping("/benchmark/sec/idor")
public class IdorSafe {

    /**
     * 安全示例：从会话获取当前登录用户，校验与请求目标一致。
     */
    @GetMapping("/safe/user-profile")
    public String safeGetUserProfile(@RequestParam Integer userId) {
        Integer currentUserId = getCurrentLoggedInUserId();
        String currentUserRole = getCurrentUserRole();
        // 安全实践：普通用户只能查看自己的信息；管理员需额外校验
        // [CHECKPOINT id=JSEF-IDOR-002S cwe=639 level=L1 source=@RequestParam userId sink=owner check before return (no IDOR) expect=SAFE]
        if (!currentUserId.equals(userId) && !"ADMIN".equals(currentUserRole)) {
            return "{'error': 'Access denied'}";
        }
        if (userId == 1) {
            return "{'userId': 1, 'username': 'admin', 'email': 'admin@example.com'}";
        } else if (userId == 2) {
            return "{'userId': 2, 'username': 'test', 'email': 'test@example.com'}";
        }
        return "{'error': 'User not found'}";
    }

    private Integer getCurrentLoggedInUserId() {
        return 2;
    }

    private String getCurrentUserRole() {
        return "USER";
    }
}
