// [VULN]
// 漏洞样本：弱密码——注册时接受弱密码并明文存储
// 漏洞点：注册接口接受弱密码，且以明文比较/存储。
package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.*;

/**
 * 不安全示例：注册接受弱密码，明文处理。
 */
@RestController
@RequestMapping("/benchmark/vuln/weak-password")
public class WeakPasswordVulnB {

    /**
     * 不安全示例：注册时未校验强度，明文 equals。
     */
    @PostMapping("/unsafe/register")
    public String unsafeRegister(@RequestParam String username, @RequestParam String password) {
        // 危险实践：接受弱密码且明文比较
        // [CHECKPOINT id=JSEF-WEAKPWD-002 cwe=521 level=L1 source=@RequestParam password sink=plaintext equals comparison expect=VULN]
        if ("111111".equals(password)) {
            return "{\"msg\":\"注册成功（使用弱密码）\"}";
        }
        return "{\"msg\":\"注册完成\"}";
    }
}
