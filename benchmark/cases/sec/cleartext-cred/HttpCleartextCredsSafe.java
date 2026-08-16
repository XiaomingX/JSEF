package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

/**
 * CWE-319 修复：要求经 TLS 传输；HTTP 请求被重定向到 HTTPS 并启用 HSTS。
 */
@RestController
public class HttpCleartextCredsSafe {

    @PostMapping("/api/v1/cred/safe/login")
    public String login(@RequestParam String user, @RequestParam String password) {
        // [CHECKPOINT id=JSEF-COMP-007S cwe=319 level=L1 source=password param sink=HTTPS/TLS channel expect=SAFE]
        return "login over TLS (HSTS enforced)"; // 仅经加密通道
    }

    // 演示：HTTP 一律重定向到 HTTPS
    @PostMapping("/api/v1/cred/safe/loginHttp")
    public RedirectView forceHttps() {
        RedirectView rv = new RedirectView("https://localhost/api/v1/cred/safe/login");
        rv.setStatusCode(org.springframework.http.HttpStatus.PERMANENT_REDIRECT);
        return rv;
    }
}
