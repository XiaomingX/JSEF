package com.freedom.securitysamples.api.cryptoVuln;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 加密机制漏洞示例控制器
 * 说明：加密实现不当会导致敏感信息泄露、身份认证绕过等严重安全问题
 * 常见加密风险：
 * 1. 使用不安全的加密算法或模式（如MD5、SHA1、ECB模式）
 * 2. 硬编码密钥/盐值，导致密钥泄露后批量数据可被破解
 * 3. 密码哈希未使用足够的工作因子，易被暴力破解
 * 4. 未处理长输入导致的安全问题（截断、DoS攻击）
 * 5. 错误的 credential 组合方式导致的安全弱化
 * 修复原则：
 * 1. 使用经过验证的现代加密算法（如BCrypt、PBKDF2WithHmacSHA256、AES-GCM）
 * 2. 为每个用户生成随机唯一的盐值
 * 3. 设置足够强度的工作因子（迭代次数），并随硬件发展调整
 * 4. 限制输入长度，防止DoS攻击
 * 5. 单独处理每个敏感字段，避免不当组合
 */
@RestController
@RequestMapping("/security-example/crypto-vulnerabilities")
public class EncryptController {

    // BCrypt密码编码器（使用默认工作因子，实际应根据需求调整）
    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(12);
    // 安全随机数生成器，用于生成盐值等随机数据
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * 不安全示例：BCrypt加密组合凭据（用户名+密码）
     * 漏洞点：
     * 1. 将用户名与密码拼接后加密，而非单独加密密码，增加暴露面
     * 2. 未明确处理BCrypt的72字节截断限制，可能导致长密码安全弱化
     * 3. 未对输入长度进行限制，存在潜在的DoS风险
     * 风险示例：
     * - 当密码长度超过72字节时，超出部分会被截断，攻击者可利用此特性构造等效密码
     * - 组合加密方式可能泄露用户名与密码的关联性，增加 credential stuffing 攻击成功率
     */
    @GetMapping("/unsafe/bcrypt-combined")
    public Map<String, String> unsafeBcryptWithCombinedCredentials(
            @RequestParam String username, 
            @RequestParam String password) {
        
        // 危险实践：将用户名和密码拼接后加密，而非单独处理密码
        String combinedCredentials = username + "|" + password;
        String encryptedValue = bCryptPasswordEncoder.encode(combinedCredentials);
        
        Map<String, String> response = new HashMap<>();
        response.put("username", username);
        response.put("encryptedCombinedValue", encryptedValue);
        response.put("warning", "此实现存在安全隐患，不应在生产环境使用");
        return response;
    }

    /**
     * 不安全示例：PBKDF2加密实现（存在多个安全缺陷）
     * 漏洞点：
     * 1. 使用硬编码盐值（"12345678"），所有用户共享相同盐值，易被彩虹表攻击
     * 2. 迭代次数（10000）过低，现代硬件可轻易暴力破解
     * 3. 未限制密码长度，长密码会导致每次迭代的预哈希操作消耗过多资源，存在DoS风险
     * 4. 未处理HMAC碰撞问题（长密码与其实哈希值作为密码会生成相同密钥）
     * 风险示例：
     * - 攻击者可利用彩虹表快速破解使用相同盐值的所有密码哈希
     * - 恶意用户提交超长密码（如10MB）可导致服务器资源耗尽
     * - 攻击者可构造不同密码却得到相同加密结果，绕过身份验证
     */
    @GetMapping("/unsafe/pbkdf2")
    public Map<String, String> unsafePbkdf2Implementation(@RequestParam String password) {
        try {
            // 危险实践1：硬编码盐值，所有加密使用相同盐
            byte[] staticSalt = "12345678".getBytes();
            // 危险实践2：迭代次数过低（现代推荐至少65536次）
            int lowIterations = 10000;
            
            char[] passwordChars = password.toCharArray();
            PBEKeySpec spec = new PBEKeySpec(
                passwordChars, 
                staticSalt, 
                lowIterations, 
                256 // 密钥长度
            );
            
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashValue = keyFactory.generateSecret(spec).getEncoded();
            String encodedHash = Base64.getEncoder().encodeToString(hashValue);
            
            Map<String, String> response = new HashMap<>();
            response.put("inputPassword", "[已隐藏]");
            response.put("pbkdf2Hash", encodedHash);
            response.put("warning", "此PBKDF2实现存在多个安全缺陷，禁止用于生产环境");
            return response;
            
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("PBKDF2加密过程发生错误", e);
        }
    }

    /**
     * 安全示例：BCrypt密码加密（最佳实践）
     * 安全改进：
     * 1. 单独加密密码，不与其他字段组合
     * 2. 明确处理密码长度限制（超过72字节时截断并警告）
     * 3. 使用合适的工作因子（12），平衡安全性和性能
     * 4. 内部自动生成随机盐值，无需手动管理
     */
    @GetMapping("/safe/bcrypt-password")
    public Map<String, String> safeBcryptPasswordEncryption(@RequestParam String password) {
        // 安全实践1：检查密码长度，处理BCrypt的72字节限制
        if (password.getBytes().length > 72) {
            password = new String(password.getBytes(), 0, 72); // 截断超长密码
        }
        
        // 安全实践2：单独加密密码，BCrypt内部会自动生成随机盐
        String secureHash = bCryptPasswordEncoder.encode(password);
        
        Map<String, String> response = new HashMap<>();
        response.put("passwordStatus", "密码已安全加密");
        response.put("bcryptHash", secureHash);
        response.put("securityNote", "使用BCrypt算法，自动生成随机盐，工作因子12");
        return response;
    }

    /**
     * 安全示例：PBKDF2加密实现（最佳实践）
     * 安全改进：
     * 1. 为每个加密操作生成随机盐值（16字节）
     * 2. 使用足够的迭代次数（65536），抵御暴力破解
     * 3. 限制密码最大长度（1024字符），防止DoS攻击
     * 4. 存储盐值与哈希结果，用于后续验证
     */
    @GetMapping("/safe/pbkdf2")
    public Map<String, String> safePbkdf2Implementation(@RequestParam String password) {
        try {
            // 安全实践1：限制密码长度，防止DoS攻击
            if (password.length() > 1024) {
                throw new IllegalArgumentException("密码长度不能超过1024字符");
            }
            
            // 安全实践2：生成随机盐值（16字节是推荐长度）
            byte[] randomSalt = new byte[16];
            SECURE_RANDOM.nextBytes(randomSalt);
            
            // 安全实践3：使用足够高的迭代次数（根据硬件能力调整）
            int secureIterations = 65536;
            
            char[] passwordChars = password.toCharArray();
            PBEKeySpec spec = new PBEKeySpec(
                passwordChars, 
                randomSalt, 
                secureIterations, 
                256 // 密钥长度
            );
            
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashValue = keyFactory.generateSecret(spec).getEncoded();
            
            // 安全实践4：存储盐值（Base64编码）和哈希结果
            String encodedSalt = Base64.getEncoder().encodeToString(randomSalt);
            String encodedHash = Base64.getEncoder().encodeToString(hashValue);
            
            Map<String, String> response = new HashMap<>();
            response.put("passwordStatus", "密码已安全加密");
            response.put("salt", encodedSalt); // 实际应用中需与哈希一起存储
            response.put("pbkdf2Hash", encodedHash);
            response.put("securityNote", "使用随机盐值，65536次迭代，SHA-256哈希函数");
            return response;
            
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("PBKDF2加密过程发生错误", e);
        }
    }
}
