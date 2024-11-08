package com.freedom.securitysamples.api.cryptoVuln;

import org.springframework.web.bind.annotation.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@RestController
@RequestMapping("/api")
public class CryptoVulnController {

    // 1. 使用不安全的加密算法
    @GetMapping("/crypto/weak-algorithm")
    public String useWeakAlgorithm() throws Exception {
        String data = "sensitive data";
        Cipher cipher = Cipher.getInstance("DES"); // DES是一个脆弱的加密算法
        return "使用了不安全的DES加密";
    }

    // 2. 使用固定的IV
    @GetMapping("/crypto/static-iv")
    public String useStaticIV() throws Exception {
        byte[] staticIv = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        IvParameterSpec iv = new IvParameterSpec(staticIv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        return "使用了固定的IV";
    }

    // 3. 使用不安全的哈希算法
    @GetMapping("/crypto/weak-hash")
    public String useWeakHash() throws Exception {
        String password = "password123";
        MessageDigest md = MessageDigest.getInstance("MD5");
        return "使用了不安全的MD5哈希";
    }

    // 4. 使用硬编码的密钥
    @GetMapping("/crypto/hardcoded-key")
    public String useHardcodedKey() {
        String key = "1234567890abcdef";
        return "使用了硬编码的密钥: " + key;
    }

    // 5. 使用短密钥
    @GetMapping("/crypto/short-key")
    public String useShortKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(64);
        return "使用了过短的密钥长度: 64位";
    }

    // 6. 不安全的随机数生成
    @GetMapping("/crypto/weak-random")
    public String useWeakRandom() {
        java.util.Random random = new java.util.Random(); // 使用不安全的随机数生成器
        return "使用了不安全的随机数生成器";
    }

    // 7. ECB模式加密
    @GetMapping("/crypto/ecb-mode")
    public String useECBMode() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // ECB模式不安全
        return "使用了不安全的ECB模式";
    }

    // 8. 不安全的密钥派生
    @GetMapping("/crypto/weak-key-derivation")
    public String useWeakKeyDerivation() throws Exception {
        String password = "password123";
        byte[] key = password.getBytes(); // 直接使用密码作为密钥
        return "使用了不安全的密钥派生方法";
    }

    // 9. 重用加密密钥对多个用途
    @GetMapping("/crypto/key-reuse")
    public String reuseKey() throws Exception {
        SecretKeySpec key = new SecretKeySpec("1234567890abcdef".getBytes(), "AES");
        // 同一个密钥用于加密和MAC
        return "重用了加密密钥";
    }

    // 10. 不安全的密码存储
    @GetMapping("/crypto/weak-password-storage")
    public String useWeakPasswordStorage() throws Exception {
        String password = "userPassword";
        String hashedPassword = Base64.getEncoder().encodeToString(password.getBytes());
        return "使用了不安全的密码存储方式";
    }

    // 11. 缺少完整性检查
    @GetMapping("/crypto/no-integrity")
    public String noIntegrityCheck() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // 没有使用MAC或签名验证
        return "缺少完整性检查";
    }

    // 12. 不安全的密钥交换
    @GetMapping("/crypto/weak-key-exchange")
    public String useWeakKeyExchange() {
        // 明文传输密钥
        String secretKey = "secretKey123";
        return "使用了不安全的密钥交换方式";
    }

    // 13. 使用过时的SSL/TLS版本
    @GetMapping("/crypto/old-tls")
    public String useOldTLS() {
        // 使用SSLv3或TLS 1.0
        return "使用了过时的TLS版本";
    }

    // 14. 不安全的PRNG种子
    @GetMapping("/crypto/weak-prng-seed")
    public String useWeakPRNGSeed() {
        SecureRandom random = new SecureRandom();
        random.setSeed(System.currentTimeMillis()); // 使用时间戳作为种子
        return "使用了不安全的PRNG种子";
    }

    // 15. 密码学操作异常处理不当
    @GetMapping("/crypto/poor-error-handling")
    public String poorErrorHandling() {
        try {
            throw new Exception("加密操作失败");
        } catch (Exception e) {
            return e.getMessage(); // 直接返回异常信息
        }
    }
}