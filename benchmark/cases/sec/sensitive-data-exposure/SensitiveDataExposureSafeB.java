// [SAFE]
// 安全对照：敏感数据泄露（场景二，修复版）
// 修复原则：不返回明文密码与安全答案，必要时脱敏。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：用户资料返回脱敏，无明文密码/安全答案。
 */
@RestController
@RequestMapping("/benchmark/sec/sensitive-data-exposure")
public class SensitiveDataExposureSafeB {

    /**
     * 安全示例：仅返回必要脱敏字段。
     */
    @GetMapping("/user-info/safe2")
    public String getUserInfoSafe2(@RequestParam String userId) {
        // 安全实践：密码与安全答案不返回
        // [CHECKPOINT id=JSEF-SENSITIVE-002S cwe=532 level=L1 source=@RequestParam userId sink=response body (masked, no plaintext password/securityAnswer) expect=SAFE]
        return "{" +
                "\"userId\": \"" + userId + "\"," +
                "\"password\": \"******\"," +
                "\"securityAnswer\": \"已隐藏\"" +
                "}";
    }
}
