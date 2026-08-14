// [SAFE]
// 安全对照：弱密码（修复版）
// 修复原则：使用强哈希（如 BCrypt）存储密码，拒绝常见弱密码，不在响应泄露明文。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 安全示例：登录时使用哈希比对且拒绝弱密码。
 */
@RestController
@RequestMapping("/benchmark/sec/weak-password")
public class WeakPasswordSafe {

    /**
     * 安全示例：拒绝常见弱密码，并使用哈希比对（非明文 equals）。
     */
    @PostMapping("/safe/login")
    public String safeLoginWithWeakPassword(
            @RequestParam String username,
            @RequestParam String password) {
        // 安全实践：拒绝弱密码字典
        if (isCommonWeakPassword(password)) {
            return "{\"msg\":\"登录失败：弱密码\"}";
        }
        // 安全实践：使用哈希比对而非明文 equals
        // [CHECKPOINT id=JSEF-WEAKPWD-001S cwe=521 level=L1 source=@RequestParam password sink=password hashing compare (no plaintext equals, weak-password rejected) expect=SAFE]
        if (verifyPasswordHash(password, getStoredHash(username))) {
            return "{\"msg\":\"登录成功（密码安全）\",\"username\":\"" + username + "\"}";
        }
        return "{\"msg\":\"登录失败\"}";
    }

    private boolean isCommonWeakPassword(String password) {
        String[] weak = {"123456", "password", "admin", "abc123", "qwerty"};
        for (String w : weak) {
            if (w.equals(password)) return true;
        }
        return false;
    }

    private String getStoredHash(String username) {
        return "stored_bcrypt_hash_placeholder";
    }

    private boolean verifyPasswordHash(String input, String storedHash) {
        // 生产环境应使用 BCrypt.checkpw(input, storedHash)
        return !isCommonWeakPassword(input) && storedHash != null;
    }
}
