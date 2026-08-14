// [SAFE]
// 安全对照：敏感数据泄露（修复版）
// 修复原则：数据最小化 + 脱敏处理；密码不返回，身份证/银行卡/手机号做掩码。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 安全示例：返回脱敏后的用户数据，不含明文密码等高度敏感字段。
 */
@RestController
@RequestMapping("/benchmark/sec/sensitive-data")
public class SensitiveDataExposureSafe {

    /**
     * 安全示例：仅返回必要且脱敏后的信息。
     */
    @GetMapping("/user-info/safe")
    public String getUserInfoSafe(@RequestParam String userId) {
        // 安全实践：密码不返回；身份证/银行卡/手机号做掩码脱敏
        // [CHECKPOINT id=JSEF-SENSITIVE-001S cwe=532 level=L1 source=@RequestParam userId sink=response body (masked, no plaintext password/idCard/creditCard) expect=SAFE]
        return "{" +
                "\"userId\": \"" + userId + "\"," +
                "\"username\": \"admin\"," +
                "\"idCard\": \"330106**********34\"," +
                "\"creditCard\": \"622202**********0123\"," +
                "\"phoneNumber\": \"138****8000\"" +
                "}";
    }
}
