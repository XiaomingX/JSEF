// [SAFE]
// 安全对照：弱密码注册（修复版）
// 修复原则：注册时校验密码强度、拒绝弱密码、以哈希存储。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：注册时校验强度并拒绝弱密码。
 */
@RestController
@RequestMapping("/benchmark/sec/weak-password")
public class WeakPasswordSafeB {

    /**
     * 安全示例：拒绝弱密码，使用哈希存储。
     */
    @PostMapping("/safe/register")
    public String safeRegister(@RequestParam String username, @RequestParam String password) {
        if (isCommonWeakPassword(password) || !isStrong(password)) {
            return "{\"msg\":\"注册失败：密码强度不足或为弱密码\"}";
        }
        // 安全实践：哈希存储，非明文比较
        // [CHECKPOINT id=JSEF-WEAKPWD-002S cwe=521 level=L1 source=@RequestParam password sink=password hashing store (weak rejected) expect=SAFE]
        storeHash(username, hash(password));
        return "{\"msg\":\"注册成功（密码安全）\"}";
    }

    private boolean isCommonWeakPassword(String p) {
        String[] weak = {"111111", "123456", "password", "admin"};
        for (String w : weak) if (w.equals(p)) return true;
        return false;
    }

    private boolean isStrong(String p) {
        if (p.length() < 8) return false;
        boolean u = false, l = false, d = false;
        for (char c : p.toCharArray()) {
            if (Character.isUpperCase(c)) u = true;
            else if (Character.isLowerCase(c)) l = true;
            else if (Character.isDigit(c)) d = true;
        }
        return u && l && d;
    }

    private String hash(String p) {
        return "bcrypt_placeholder";
    }

    private void storeHash(String u, String h) {
        // 存储哈希
    }
}
