// [VULN]
// 漏洞样本：敏感数据泄露——响应中包含明文密码与安全问题答案
// 漏洞点：返回用户数据时泄露明文密码与安全问题答案。
package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.*;

/**
 * 不安全示例：返回包含明文密码等敏感字段。
 */
@RestController
@RequestMapping("/benchmark/vuln/sensitive-data-exposure")
public class SensitiveDataExposureVulnB {

    /**
     * 不安全示例：响应返回明文密码与安全答案。
     */
    @GetMapping("/user-info/unsafe2")
    public String getUserInfoUnsafe2(@RequestParam String userId) {
        // 危险实践：明文密码与安全答案直接返回
        // [CHECKPOINT id=JSEF-SENSITIVE-002 cwe=532 level=L1 source=@RequestParam userId sink=response body (plaintext password/securityAnswer) expect=VULN]
        return "{" +
                "\"userId\": \"" + userId + "\"," +
                "\"password\": \"secret123\"," +
                "\"securityAnswer\": \"我的宠物叫豆豆\"" +
                "}";
    }
}
