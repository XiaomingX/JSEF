// [VULN]
// 漏洞样本：默认凭证——硬编码的物联网设备后台凭证
// 漏洞点：设备后台使用硬编码默认 admin/admin 凭证，未强制修改。
package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.*;

/**
 * 不安全示例：物联网设备默认凭证硬编码。
 */
@RestController
@RequestMapping("/benchmark/vuln/default-credentials")
public class DefaultCredentialsVulnB {

    private static final String DEVICE_ADMIN = "admin";
    private static final String DEVICE_PASS = "admin";

    /**
     * 不安全示例：直接使用硬编码默认凭证校验登录。
     */
    @GetMapping("/unsafe/device-login")
    public String unsafeDeviceLogin(@RequestParam String username, @RequestParam String password) {
        // 危险实践：硬编码默认设备凭证
        // [CHECKPOINT id=JSEF-DEFAULTCRED-002 cwe=798 level=L1 source=DEVICE_ADMIN/DEVICE_PASS sink=auth check expect=VULN]
        if (DEVICE_ADMIN.equals(username) && DEVICE_PASS.equals(password)) {
            return "{\"status\":\"success\",\"msg\":\"默认凭证登录成功（危险）\"}";
        }
        return "{\"status\":\"failed\"}";
    }
}
