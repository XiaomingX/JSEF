package com.freedom.securitysamples.api.insecureDirectObjectReference;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/insecureDirectObjectReference")
public class UserProfileController {

    // 1. 原有的不安全用户信息查询接口
    @GetMapping("/user/profile")
    public String getUserProfile(@RequestParam Integer userId) {
        // 不安全实现:直接根据用户ID返回信息,没有权限验证
        if (userId == 1) {
            return "{'userId': 1, 'username': 'admin', 'email': 'admin@example.com', 'phone': '13800138000'}";
        } else if (userId == 2) {
            return "{'userId': 2, 'username': 'test', 'email': 'test@example.com', 'phone': '13900139000'}";
        }
        return "{'error': 'User not found'}";
    }

    // 2. 不安全的文件下载接口
    @GetMapping("/download/file")
    public String downloadFile(@RequestParam String fileName) {
        // 不安全实现:直接根据文件名下载,可能导致任意文件下载
        return "Download file content: " + fileName;
    }

    // 3. 不安全的订单查询接口
    @GetMapping("/order/detail")
    public String getOrderDetail(@RequestParam String orderId) {
        // 不安全实现:未验证订单是否属于当前用户
        return "{'orderId': '" + orderId + "', 'amount': 100, 'userInfo': 'sensitive data'}";
    }

    // 4. 不安全的用户配置修改接口
    @PostMapping("/user/settings")
    public String updateUserSettings(@RequestParam Integer userId, @RequestParam String settings) {
        // 不安全实现:未验证是否有权限修改目标用户配置
        return "Updated settings for user: " + userId;
    }

    // 5. 不安全的支付记录查询接口
    @GetMapping("/payment/history")
    public String getPaymentHistory(@RequestParam String accountId) {
        // 不安全实现:未验证账户所有权
        return "{'accountId': '" + accountId + "', 'balance': 10000, 'transactions': []}";
    }

    // 6. 不安全的文档访问接口
    @GetMapping("/document/view")
    public String viewDocument(@RequestParam Integer docId) {
        // 不安全实现:未检查文档访问权限
        return "Document content for id: " + docId;
    }

    // 7. 不安全的API密钥查看接口
    @GetMapping("/api/keys")
    public String getApiKeys(@RequestParam String username) {
        // 不安全实现:未验证用户身份就返回API密钥
        return "{'apiKey': 'sensitive-api-key-value', 'username': '" + username + "'}";
    }

    // 8. 不安全的用户角色修改接口
    @PostMapping("/user/role")
    public String updateUserRole(@RequestParam Integer userId, @RequestParam String newRole) {
        // 不安全实现:未验证操作者权限
        return "Updated role to " + newRole + " for user: " + userId;
    }

    // 9. 不安全的系统日志查询接口
    @GetMapping("/system/logs")
    public String getSystemLogs(@RequestParam String date) {
        // 不安全实现:未验证查看系统日志的权限
        return "System logs for date: " + date;
    }

    // 10. 不安全的个人消息查询接口
    @GetMapping("/messages")
    public String getUserMessages(@RequestParam Integer userId) {
        // 不安全实现:未验证消息查看权限
        return "Messages for user: " + userId;
    }
}