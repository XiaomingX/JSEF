// [SAFE]
// 安全对照：IDOR 订单越权（修复版）
// 修复原则：查询订单时关联当前登录用户，仅返回自己的订单。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：订单详情查询校验归属。
 */
@RestController
@RequestMapping("/benchmark/sec/idor")
public class IdorSafeB {

    /**
     * 安全示例：仅返回当前用户自己的订单。
     */
    @GetMapping("/safe/order-detail")
    public String safeGetOrderDetail(@RequestParam String orderId) {
        Integer currentUserId = getCurrentLoggedInUserId();
        // 安全实践：订单归属校验
        // [CHECKPOINT id=JSEF-IDOR-003S cwe=639 level=L1 source=@RequestParam orderId sink=owner check before order return expect=SAFE]
        if (!orderBelongsToUser(orderId, currentUserId)) {
            return "{'error': 'Access denied: 订单不属于当前用户'}";
        }
        return "{'orderId': '" + orderId + "', 'amount': 100}";
    }

    private Integer getCurrentLoggedInUserId() {
        return 2;
    }

    private boolean orderBelongsToUser(String orderId, Integer userId) {
        // 演示：仅 orderId 以当前用户前缀开头才允许
        return orderId != null && orderId.startsWith("U" + userId + "_");
    }
}
