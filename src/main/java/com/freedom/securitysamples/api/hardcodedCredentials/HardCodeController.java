package com.freedom.securitysamples.api.hardcodedCredentials;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.sql.Connection;
import java.sql.DriverManager;

@RestController
@RequestMapping("/api")
public class HardCodeController {

    // 1. 原始的不安全示例
    @GetMapping("/hardPassword/bad01")
    public String retrieveHardCodedPassword(){
        String secretPassword = "letMeIn!";
        String apiAccessKeyId = "letMeIn!";
        String apiAccessKeySecret = "letMeIn!";
        return "{'msg':'success'}";
    }

    // 2. 数据库连接中的硬编码凭证
    @GetMapping("/hardPassword/bad02")
    public String dbConnection() {
        try {
            String url = "jdbc:mysql://localhost:3306/test";
            String username = "root";
            String password = "123456";
            Connection conn = DriverManager.getConnection(url, username, password);
            return "{'msg':'connected'}";
        } catch(Exception e) {
            return "{'msg':'error'}";
        }
    }

    // 3. 硬编码的API密钥
    @GetMapping("/hardPassword/bad03")
    public String apiKeys() {
        final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
        final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        return "{'msg':'api keys set'}";
    }

    // 4. 硬编码的加密密钥
    @GetMapping("/hardPassword/bad04")
    public String encryptionKey() {
        String encryptionKey = "MySecretEncryptionKey123!";
        String initVector = "RandomInitVector";
        return "{'msg':'encryption ready'}";
    }

    // 5. 硬编码的认证令牌
    @GetMapping("/hardPassword/bad05")
    public String authToken() {
        String bearerToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
        String refreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
        return "{'msg':'tokens set'}";
    }

    // 6. 硬编码的第三方服务凭证
    @GetMapping("/hardPassword/bad06")
    public String thirdPartyCredentials() {
        String paypalClientId = "client_id_12345";
        String paypalSecret = "client_secret_67890";
        String stripeApiKey = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";
        return "{'msg':'third party credentials set'}";
    }

    // 7. 硬编码的管理员凭证
    @GetMapping("/hardPassword/bad07")
    public String adminCredentials() {
        String adminUsername = "admin";
        String adminPassword = "admin123";
        return "{'msg':'admin credentials set'}";
    }

    // 8. 硬编码的SSH密钥
    @GetMapping("/hardPassword/bad08")
    public String sshKeys() {
        String privateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA...";
        String publicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...";
        return "{'msg':'ssh keys set'}";
    }
}