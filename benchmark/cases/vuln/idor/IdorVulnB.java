// [VULN]
// 漏洞样本：IDOR——订单详情越权查看（未验证订单归属）
// 漏洞点：仅通过 orderId 查询订单，未验证该订单是否属于当前登录用户。
package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.*;

/**
 * 不安全示例：订单详情查询缺乏归属校验。
 */
@RestController
@RequestMapping("/benchmark/vuln/idor")
public class IdorVulnB {

    /**
     * 不安全示例：直接按 orderId 返回订单，无 owner 检查。
     */
    @GetMapping("/unsafe/order-detail")
    public String unsafeGetOrderDetail(@RequestParam String orderId) {
        // 危险实践：未验证订单归属当前用户
        // [CHECKPOINT id=JSEF-IDOR-003 cwe=639 level=L1 source=@RequestParam orderId sink=order return (no owner check) expect=VULN]
        return "{'orderId': '" + orderId + "', 'amount': 100, 'userInfo': 'sensitive data'}";
    }
}
