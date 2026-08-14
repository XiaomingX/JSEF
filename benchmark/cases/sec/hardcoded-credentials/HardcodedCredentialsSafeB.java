// [SAFE]
// 安全对照：硬编码 SMTP 凭证（修复版）
// 修复原则：SMTP 凭证来自环境变量/密钥管理，不硬编码。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：邮件发送使用外部化凭证。
 */
@RestController
@RequestMapping("/benchmark/sec/hardcoded-credentials")
public class HardcodedCredentialsSafeB {

    /**
     * 安全示例：从环境变量读取 SMTP 密码。
     */
    @GetMapping("/safe/send-mail")
    public String safeSendMail(@RequestParam String to) {
        String smtpHost = System.getenv("SMTP_HOST");
        String smtpUser = System.getenv("SMTP_USER");
        String smtpPassword = System.getenv("SMTP_PASSWORD");
        if (smtpPassword == null) {
            return "{\"msg\":\"SMTP 凭证未配置\"}";
        }
        // 安全实践：凭证外部化，代码中无硬编码
        // [CHECKPOINT id=JSEF-HARDCODED-002S cwe=798 level=L1 source=env var (not hardcoded) sink=mail transport connect (secrets externalized) expect=SAFE]
        return "{\"msg\":\"邮件已发送（凭证来自外部配置）\"}";
    }
}
