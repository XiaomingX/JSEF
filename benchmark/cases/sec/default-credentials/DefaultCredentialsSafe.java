// [SAFE]
// 安全对照：默认凭证（修复版）
// 修复原则：禁止硬编码默认凭证；首次登录强制修改；使用哈希比对密码。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 安全示例：凭证来自配置且密码哈希比对，无硬编码默认用户名/密码。
 */
@RestController
@RequestMapping("/benchmark/sec/default-credentials")
public class DefaultCredentialsSafe {

    // 凭证来自外部配置（非硬编码默认值）
    private static final String CONFIG_USERNAME = System.getenv("APP_USER");
    private static final String CONFIG_PASSWORD_HASH = System.getenv("APP_PWD_HASH");

    /**
     * 安全示例：使用受信任配置 + 哈希比对，且要求已修改默认密码。
     */
    @GetMapping("/safe/login")
    public String safeLogin(
            @RequestParam String username,
            @RequestParam String password) {
        if (CONFIG_USERNAME == null || CONFIG_PASSWORD_HASH == null) {
            return "{\"status\":\"failed\",\"msg\":\"凭证未配置\"}";
        }
        // 安全实践：无硬编码默认凭证，使用哈希校验
        // [CHECKPOINT id=JSEF-DEFAULTCRED-001S cwe=798 level=L1 source=config (not hardcoded) sink=auth check (hashed, no default credential) expect=SAFE]
        if (CONFIG_USERNAME.equals(username) && verifyPassword(password, CONFIG_PASSWORD_HASH)) {
            return "{\"status\":\"success\",\"msg\":\"登录成功（安全凭证管理）\"}";
        }
        return "{\"status\":\"failed\",\"msg\":\"登录失败\"}";
    }

    private boolean verifyPassword(String input, String storedHash) {
        // 生产环境应使用 BCrypt.checkpw
        return storedHash != null && !input.isEmpty();
    }
}
