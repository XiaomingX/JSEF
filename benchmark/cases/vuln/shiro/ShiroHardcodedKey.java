package com.jsef.benchmark.vuln;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-502 Shiro 反序列化（教学级触发点演示，不含 gadget 链）：
 * Apache Shiro 的 rememberMe 功能用 AES-CBC 加密序列化对象，密钥来源于
 * 硬编码默认值。一旦密钥泄露，攻击者可构造恶意序列化 payload 经 rememberMe
 * cookie 触发反序列化。本样本仅展示"硬编码密钥"这一危险触发点，不含任何可用
 * gadget 链或可连接恶意服务地址。
 *
 * 修复（见 sec）：使用随机生成且外部化存储的密钥（shiro.key 配置），不提交源码。
 */
@RestController
public class ShiroHardcodedKey {

    // 硬编码 AES 密钥（教学演示：等同于 Shiro 历史默认密钥 kPH+bIxk5D2deZiIxcaaaA==）
    private static final String HARDCODED_KEY = "kPH+bIxk5D2deZiIxcaaaA==";

    @PostMapping("/api/v1/shiro/unsafe/remember")
    public String remember(@RequestParam String payload) throws Exception {
        byte[] key = java.util.Base64.getDecoder().decode(HARDCODED_KEY);
        // [CHECKPOINT id=JSEF-COMP-009 cwe=502 level=L2 source=rememberMe cookie sink=AES key (hardcoded) -> deserialize expect=VULN]
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES")); // 密钥硬编码
        return "rememberMe cookie issued with fixed key";
    }
}
