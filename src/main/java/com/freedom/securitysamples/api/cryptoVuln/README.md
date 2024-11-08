我来帮你更新代码，展示几个包含加密算法漏洞(cryptoVuln)的示例。以下是几种常见的加密相关漏洞场景：

```java
package com.freedom.securitysamples.api.cryptoVuln;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
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
    public String useStaticIV() {
        return "使用了固定的IV: 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00";
    }

    // 3. 使用不安全的哈希算法
    @GetMapping("/crypto/weak-hash")
    public String useWeakHash() throws Exception {
        String password = "password123";
        MessageDigest md = MessageDigest.getInstance("MD5"); // MD5是不安全的哈希算法
        return "使用了不安全的MD5哈希";
    }

    // 4. 使用硬编码的密钥
    @GetMapping("/crypto/hardcoded-key")
    public String useHardcodedKey() {
        String key = "1234567890abcdef"; // 硬编码的密钥是不安全的
        return "使用了硬编码的密钥: " + key;
    }

    // 5. 使用短密钥
    @GetMapping("/crypto/short-key")
    public String useShortKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(64); // 64位密钥长度过短
        return "使用了过短的密钥长度: 64位";
    }
}
```

这些示例展示了几种常见的加密算法漏洞：

1. 使用弱加密算法（如DES）
2. 使用静态/固定的初始化向量(IV)
3. 使用不安全的哈希算法（如MD5）
4. 在代码中硬编码密钥
5. 使用过短的密钥长度

每个方法都返回一个字符串，说明了具体的漏洞情况。这些都是实际开发中应该避免的不安全加密实践。建议使用：

- 强加密算法（如AES-256）
- 随机生成的IV
- 安全的哈希算法（如SHA-256或更新的算法）
- 通过安全的密钥管理系统管理密钥
- 足够长的密钥长度（如AES使用256位）