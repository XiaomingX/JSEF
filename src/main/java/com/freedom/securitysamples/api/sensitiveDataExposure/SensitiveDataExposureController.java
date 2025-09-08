package com.freedom.securitysamples.api.sensitiveDataExposure;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 敏感数据泄露漏洞示例控制器
 * 说明：敏感数据泄露是指未对个人隐私或敏感信息进行保护，导致信息被未授权访问
 * 常见风险：身份证号、银行卡号、密码、手机号等信息泄露可能引发诈骗、身份盗用等安全事件
 * 修复原则：
 * 1. 数据最小化：只返回必要信息，不泄露无关敏感数据
 * 2. 脱敏处理：对敏感信息进行部分隐藏（如手机号显示为138****8000）
 * 3. 加密传输：使用HTTPS确保数据传输过程安全
 * 4. 密码安全：禁止明文存储/传输密码，应存储加密后的哈希值
 */
@RestController
@RequestMapping("/security-example/sensitive-data")
public class SensitiveDataExposureController {

    /**
     * 不安全示例：返回包含大量未脱敏敏感信息的用户数据
     * 漏洞点：
     * 1. 密码以明文形式返回（严重违规）
     * 2. 身份证号、银行卡号等敏感信息完整暴露
     * 3. 未遵循数据最小化原则，返回过多不必要的隐私信息
     * 4. 未做任何脱敏处理，直接展示完整敏感数据
     */
    @GetMapping("/user-info/unsafe")
    public String getUserInfoWithSensitiveData(@RequestParam String userId) {
        // 危险实践：直接拼接并返回包含敏感信息的JSON
        // 注意：实际开发中绝不能这样处理敏感数据
        return "{" +
                "\"userId\": \"" + userId + "\"," +                  // 用户ID（非敏感）
                "\"username\": \"admin\"," +                          // 用户名（低敏感）
                "\"password\": \"admin123\"," +                       // 严重敏感：密码明文（禁止！）
                "\"idCard\": \"330106199001011234\"," +               // 高敏感：完整身份证号
                "\"creditCard\": \"6222021234567890123\"," +           // 高敏感：完整信用卡号
                "\"phoneNumber\": \"13800138000\"," +                  // 高敏感：完整手机号
                "\"email\": \"admin@company.com\"," +                  // 中敏感：邮箱地址
                "\"salary\": \"50000\"," +                             // 高敏感：薪资信息
                "\"bankAccount\": \"6217001234567890123\"," +          // 高敏感：完整银行账号
                "\"address\": \"浙江省杭州市西湖区xxx路xx号\"," +       // 高敏感：详细住址
                "\"securityQuestion\": \"我的生日是1990年1月1日\"" +     // 高敏感：安全问题答案（易被用于密码重置）
                "}";
    }
}
    