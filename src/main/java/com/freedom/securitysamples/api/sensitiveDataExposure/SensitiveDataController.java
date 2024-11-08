package com.freedom.securitysamples.api.sensitiveDataExposure;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class SensitiveDataController {

    @GetMapping("/user/info")
    public String getUserInfo(String userId) {
        // 这里直接返回包含敏感信息的JSON字符串
        return "{'userId': '" + userId + "'," +
                "'username': 'admin'," +
                "'password': 'admin123'," +  // 敏感信息：密码明文
                "'idCard': '330106199001011234'," +  // 敏感信息：身份证号
                "'creditCard': '6222021234567890123'," +  // 敏感信息：信用卡号
                "'phoneNumber': '13800138000'," +  // 敏感信息：手机号
                "'email': 'admin@company.com'," +
                "'salary': '50000'," +  // 敏感信息：工资
                "'bankAccount': '6217001234567890123'," +  // 敏感信息：银行账号
                "'address': '浙江省杭州市西湖区xxx路xx号'," +  // 敏感信息：详细地址
                "'securityQuestion': '我的生日是1990年1月1日'" +  // 敏感信息：安全问题答案
                "}";
    }
}