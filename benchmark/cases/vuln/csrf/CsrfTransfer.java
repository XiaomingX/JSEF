// [VULN]
package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark — CSRF 跨站请求伪造 (CWE-352，难度 L2)
 *
 * 危险入口：状态变更端点（转账）未校验 CSRF token，也无 SameSite / Origin 校验，
 * 攻击者可在第三方页面诱导受害者浏览器发起伪造请求。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实钓鱼页面。
 */
@RestController
public class CsrfTransfer {

    /**
     * 危险：POST 状态变更无 CSRF 防护（无 token / 无 Origin 校验）。
     */
    @PostMapping("/api/transfer")
    public String transfer(@RequestParam String to, @RequestParam double amount) {
        // [CHECKPOINT id=JSEF-CSRF-001 cwe=352 level=L2 source=forged cross-site request sink=transfer state change expect=VULN]
        // 执行转账（无 CSRF token 校验、无 Origin/Referer 同源校验、无 SameSite）
        return "transferred " + amount + " to " + to;
    }
}
