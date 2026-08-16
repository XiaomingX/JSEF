package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-319 明文传输：通过 HTTP（非 HTTPS）提交凭据，链路中被窃听即泄露。
 * 仅演示触发点：表单/接口以明文 HTTP 暴露登录。不可含真实可连接恶意地址。
 *
 * 修复：强制 HTTPS（HSTS + 服务端 302 跳转），凭据仅在 TLS 通道传输。
 */
@RestController
public class HttpCleartextCreds {

    @PostMapping("/api/v1/cred/unsafe/login")
    public String login(@RequestParam String user, @RequestParam String password) {
        // [CHECKPOINT id=JSEF-COMP-007 cwe=319 level=L1 source=password param sink=HTTP plaintext channel expect=VULN]
        return "login over cleartext HTTP"; // 无 TLS 保护
    }
}
