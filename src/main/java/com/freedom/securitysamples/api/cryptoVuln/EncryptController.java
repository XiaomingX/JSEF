package com.freedom.securitysamples.api.cryptoVuln;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v2/")
public class EncryptController {

    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    //在使用 bCrypt 加密算法时，输入的字符串会被自动截断到 72 字节。这意味着在加密时，超过 72 字节的部分将被忽略，仅前 72 字节会参与到哈希的计算中。
    //这一特性是 bCrypt 本身的限制，用于确保密码长度不会影响其哈希值的生成。
    //在 bCrypt 中，72 个字节相当于 72 个字符，因为每个 ASCII 字符（包括字母 "a"）占 1 个字节。因此，用字母 "a" 填充的话，72 个字节就是 72 个 "a"。
    @GetMapping("/encrypt")
    public Map<String, String> encrypt(@RequestParam String username, @RequestParam String password) {
        // 将用户名和密码拼接
        String combined = username + "|" + password;
        // 使用 BCrypt 进行加密
        String encrypted = bCryptPasswordEncoder.encode(combined);
        // 将结果放到 JSON 里返回
        Map<String, String> response = new HashMap<>();
        response.put("username", username);
        response.put("encrypted", encrypted);
        return response;
    }

    //    PBKDF2预哈希机制相关的拒绝服务漏洞：
    //    某些PBKDF2实现在每次迭代时都会执行预哈希操作
    //    当用户提供非常长的密码时，每次迭代都需要进行预哈希计算
    //    这导致处理长密码比短密码耗费更多资源，形成潜在的DOS攻击向量

    //    HMAC碰撞问题
    //    PBKDF2在使用HMAC作为伪随机函数时存在一个有趣的特性：
    //    可以轻易构造出具有相同哈希值的不同密码对
    //    当密码长度超过HMAC哈希函数的块大小时，会先进行预哈希
    //            这意味着原始长密码和其预哈希值作为密码会产生完全相同的密钥3
    //    例如使用HMAC-SHA1时：
    //    一个超长的密码会被预哈希成一个较短的摘要
    //            使用这个预哈希摘要作为密码会得到相同的结果
    //    这种情况下无论使用什么盐值或迭代次数，两个不同的密码都会生成相同的密钥
    
    @GetMapping("/pbkdf2-encrypt")
    public Map<String, String> pbkdf2Encrypt(@RequestParam String password) {
        // 使用 PBKDF2 进行加密
        try {
            int iterations = 10000;
            char[] chars = password.toCharArray();
            byte[] salt = "12345678".getBytes(); // 示例盐值

            PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 256);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            String encodedHash = Base64.getEncoder().encodeToString(hash);

            Map<String, String> response = new HashMap<>();
            response.put("password", password);
            response.put("pbkdf2Hash", encodedHash);
            return response;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error while encrypting password with PBKDF2", e);
        }
    }
}
