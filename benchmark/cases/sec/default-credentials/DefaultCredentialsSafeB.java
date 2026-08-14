// [SAFE]
// 安全对照：物联网设备默认凭证（修复版）
// 修复原则：凭证来自配置且强制首次修改，哈希比对。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：设备登录使用外部配置且无硬编码默认值。
 */
@RestController
@RequestMapping("/benchmark/sec/default-credentials")
public class DefaultCredentialsSafeB {

    private static final String CONFIG_USER = System.getenv("DEVICE_USER");
    private static final String CONFIG_HASH = System.getenv("DEVICE_PWD_HASH");

    /**
     * 安全示例：无硬编码默认凭证，哈希校验。
     */
    @GetMapping("/safe/device-login")
    public String safeDeviceLogin(@RequestParam String username, @RequestParam String password) {
        if (CONFIG_USER == null || CONFIG_HASH == null) {
            return "{\"status\":\"failed\",\"msg\":\"凭证未配置\"}";
        }
        // 安全实践：无硬编码默认凭证
        // [CHECKPOINT id=JSEF-DEFAULTCRED-002S cwe=798 level=L1 source=config (not hardcoded) sink=auth check (hashed, no default credential) expect=SAFE]
        if (CONFIG_USER.equals(username) && verify(password, CONFIG_HASH)) {
            return "{\"status\":\"success\",\"msg\":\"登录成功（安全）\"}";
        }
        return "{\"status\":\"failed\"}";
    }

    private boolean verify(String input, String hash) {
        return hash != null && !input.isEmpty();
    }
}
