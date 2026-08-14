// [SAFE]
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark — CSRF 安全对照 (CWE-352，难度 L2)
 *
 * 修复：校验 Origin 头与本站同源（或校验 CSRF token），拒绝跨站伪造请求。
 */
@RestController
public class CsrfTransferSafe {

    private static final String ORIGIN = "https://bank.example.com";

    /**
     * 安全：校验 Origin 同源后才执行状态变更。
     */
    @PostMapping("/api/transfer")
    public String transfer(@RequestParam String to, @RequestParam double amount,
                           @RequestHeader("Origin") String origin) {
        // [CHECKPOINT id=JSEF-CSRF-001S cwe=352 level=L2 source=Origin header sink=SameSite/Origin same-origin check expect=SAFE]
        if (!ORIGIN.equals(origin)) {
            return "forbidden: cross-site request";
        }
        return "transferred " + amount + " to " + to;
    }
}
