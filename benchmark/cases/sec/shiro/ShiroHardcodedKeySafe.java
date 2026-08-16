package com.jsef.benchmark.sec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-502 修复：密钥从外部配置（环境变量/密钥管理）随机生成，不写死在源码中。
 */
@RestController
public class ShiroHardcodedKeySafe {

    // 注意：真实密钥应由外部密钥管理注入，此处仅演示"从环境读取而非硬编码"
    private String getKey() {
        String k = System.getenv("SHIRO_KEY"); // 外部化、随机、不入库
        return k != null ? k : "CHANGE_ME_VIA_SECRET_MANAGER";
    }

    @PostMapping("/api/v1/shiro/safe/remember")
    public String remember(@RequestParam String payload) throws Exception {
        byte[] key = java.util.Base64.getDecoder().decode(getKey());
        // [CHECKPOINT id=JSEF-COMP-009S cwe=502 level=L2 source=rememberMe cookie sink=AES key (external/random) expect=SAFE]
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return "rememberMe cookie issued with external key";
    }
}
