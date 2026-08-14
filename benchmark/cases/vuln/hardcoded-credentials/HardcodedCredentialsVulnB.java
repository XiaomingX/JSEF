// [VULN]
// 漏洞样本：硬编码凭证——硬编码的 SMTP 服务密码
// 漏洞点：邮件服务凭证直接写入代码字面量。
package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.*;

/**
 * 不安全示例：SMTP 密码硬编码。
 */
@RestController
@RequestMapping("/benchmark/vuln/hardcoded-credentials")
public class HardcodedCredentialsVulnB {

    /**
     * 不安全示例：邮件发送使用硬编码密码。
     */
    @GetMapping("/unsafe/send-mail")
    public String unsafeSendMail(@RequestParam String to) {
        // 危险实践：SMTP 凭证硬编码在代码中
        String smtpHost = "smtp.example.com";
        String smtpUser = "noreply@example.com";
        String smtpPassword = "SmtpPass!2023";
        // [CHECKPOINT id=JSEF-HARDCODED-002 cwe=798 level=L1 source=hardcoded string sink=mail transport connect expect=VULN]
        return "{\"msg\":\"邮件已发送（使用硬编码 SMTP 密码）\"}";
    }
}
