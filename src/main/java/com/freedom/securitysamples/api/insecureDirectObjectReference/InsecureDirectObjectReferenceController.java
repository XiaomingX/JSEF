package com.freedom.securitysamples.api.insecureDirectObjectReference;

import org.springframework.web.bind.annotation.*;

/**
 * 不安全直接对象引用(IDOR)漏洞示例控制器
 * 说明：IDOR是指应用程序使用用户提供的输入直接访问对象（如用户ID、文件路径、订单号等），
 *       而未充分验证该用户是否有权限访问该对象，导致攻击者可访问/修改未授权资源。
 * 常见风险：
 * 1. 越权访问其他用户的敏感信息（个人资料、订单、消息等）
 * 2. 未授权修改他人数据（账户设置、权限角色等）
 * 3. 任意文件下载/访问系统敏感文件
 * 4. 泄露系统配置或密钥信息
 * 修复原则：
 * 1. 实施严格的访问控制检查：验证当前用户是否有权访问目标对象
 * 2. 使用间接引用：不直接暴露对象真实ID，使用映射后的临时标识符
 * 3. 权限验证应在所有对象访问操作前执行
 * 4. 最小权限原则：仅授予必要的访问权限
 * 5. 对敏感操作添加额外验证（如验证码、二次确认）
 */
@RestController
@RequestMapping("/security-example/idor")
public class InsecureDirectObjectReferenceController {

    /**
     * 不安全示例：用户信息查询接口（缺乏权限验证）
     * 漏洞点：
     * 1. 直接使用用户传入的userId查询数据，未验证该用户是否为当前登录用户
     * 2. 没有检查访问者是否有权限查看目标用户信息
     * 攻击示例：
     * 攻击者在请求中修改userId参数为1，即可查看管理员信息
     * GET /security-example/idor/unsafe/user-profile?userId=1
     * 修复建议：
     * 1. 获取当前登录用户的ID（如从会话或令牌中提取）
     * 2. 验证请求的userId与当前登录用户ID是否一致
     * 3. 对管理员等特殊角色的跨用户访问添加额外权限检查
     */
    @GetMapping("/unsafe/user-profile")
    public String unsafeGetUserProfile(@RequestParam Integer userId) {
        // 危险实践：直接信任用户输入的ID，没有权限验证
        if (userId == 1) {
            return "{'userId': 1, 'username': 'admin', 'email': 'admin@example.com', 'phone': '13800138000'}";
        } else if (userId == 2) {
            return "{'userId': 2, 'username': 'test', 'email': 'test@example.com', 'phone': '13900139000'}";
        }
        return "{'error': 'User not found'}";
    }

    /**
     * 不安全示例：文件下载接口（路径直接拼接）
     * 漏洞点：
     * 1. 直接使用用户传入的fileName作为文件路径，未做任何过滤和验证
     * 2. 未限制可下载文件的范围和类型
     * 攻击示例：
     * 攻击者传入../../../../etc/passwd（Linux）或../../../../windows/system32/config/sam（Windows）
     * 获取系统敏感文件
     * GET /security-example/idor/unsafe/download-file?fileName=../../../../etc/passwd
     * 修复建议：
     * 1. 将允许下载的文件限制在指定目录（白名单目录）
     * 2. 使用文件ID而非直接文件名，并维护ID与文件的映射关系
     * 3. 对用户输入的文件名进行严格过滤，禁止目录遍历字符（如../）
     * 4. 验证用户是否有权限下载该文件
     */
    @GetMapping("/unsafe/download-file")
    public String unsafeDownloadFile(@RequestParam String fileName) {
        // 危险实践：直接使用用户输入的文件名，可能导致任意文件访问
        return "Download file content: " + fileName;
    }

    /**
     * 不安全示例：订单详情查询接口（未验证订单归属）
     * 漏洞点：
     * 1. 仅通过orderId查询订单，未验证该订单是否属于当前登录用户
     * 2. 返回的订单信息包含敏感数据，未做脱敏处理
     * 攻击示例：
     * 攻击者通过遍历orderId（如1001、1002...）可查看所有用户的订单信息
     * GET /security-example/idor/unsafe/order-detail?orderId=1001
     * 修复建议：
     * 1. 查询订单时关联当前登录用户ID，确保只能查询自己的订单
     * 2. SQL查询应包含"WHERE order_id = ? AND user_id = ?"条件
     * 3. 对订单中的敏感信息进行脱敏处理
     */
    @GetMapping("/unsafe/order-detail")
    public String unsafeGetOrderDetail(@RequestParam String orderId) {
        // 危险实践：未验证订单是否属于当前请求用户
        return "{'orderId': '" + orderId + "', 'amount': 100, 'userInfo': 'sensitive data'}";
    }

    /**
     * 不安全示例：用户配置修改接口（缺乏权限校验）
     * 漏洞点：
     * 1. 允许用户指定任意userId进行配置修改，未验证操作权限
     * 2. 没有检查当前登录用户是否为目标用户或拥有管理员权限
     * 攻击示例：
     * 攻击者发送请求修改管理员配置
     * POST /security-example/idor/unsafe/update-settings?userId=1&settings=...
     * 修复建议：
     * 1. 验证当前登录用户ID与目标userId是否一致
     * 2. 若为管理员操作，需额外验证管理员权限
     * 3. 对敏感配置修改添加日志审计
     */
    @PostMapping("/unsafe/update-settings")
    public String unsafeUpdateUserSettings(@RequestParam Integer userId, @RequestParam String settings) {
        // 危险实践：未验证是否有权限修改目标用户配置
        return "Updated settings for user: " + userId;
    }

    /**
     * 不安全示例：支付记录查询接口（未验证账户所有权）
     * 漏洞点：
     * 1. 直接使用用户提供的accountId查询支付记录
     * 2. 未验证该账户是否属于当前登录用户
     * 攻击示例：
     * 攻击者猜测或遍历accountId，获取其他用户的支付历史和余额信息
     * GET /security-example/idor/unsafe/payment-history?accountId=12345
     * 修复建议：
     * 1. 从当前登录用户会话中获取账户ID，而非依赖用户输入
     * 2. 若必须接受账户ID参数，需验证该账户与用户的关联关系
     * 3. 对财务相关信息实施更严格的访问控制
     */
    @GetMapping("/unsafe/payment-history")
    public String unsafeGetPaymentHistory(@RequestParam String accountId) {
        // 危险实践：未验证账户是否属于当前用户
        return "{'accountId': '" + accountId + "', 'balance': 10000, 'transactions': []}";
    }

    /**
     * 不安全示例：文档访问接口（无权限检查）
     * 漏洞点：
     * 1. 仅通过docId查询文档，未检查当前用户是否有访问权限
     * 2. 没有验证文档的访问范围（如私有、公开、部门内共享）
     * 攻击示例：
     * 攻击者通过批量请求不同docId，访问机密文档
     * GET /security-example/idor/unsafe/view-document?docId=999
     * 修复建议：
     * 1. 实现文档权限模型（如所有者、编辑者、查看者）
     * 2. 访问文档前检查当前用户是否在授权列表中
     * 3. 对敏感文档添加访问日志
     */
    @GetMapping("/unsafe/view-document")
    public String unsafeViewDocument(@RequestParam Integer docId) {
        // 危险实践：未检查用户是否有权访问该文档
        return "Document content for id: " + docId;
    }

    /**
     * 不安全示例：API密钥查看接口（身份验证缺失）
     * 漏洞点：
     * 1. 仅通过username参数返回API密钥，未验证请求者身份
     * 2. 直接暴露敏感的API密钥信息
     * 攻击示例：
     * 攻击者传入管理员用户名，获取其API密钥
     * GET /security-example/idor/unsafe/api-keys?username=admin
     * 修复建议：
     * 1. 必须验证当前登录用户身份，且只能查看自己的API密钥
     * 2. API密钥应加密存储，展示时做部分隐藏（如显示前4后4字符）
     * 3. 添加密钥查看的审计日志
     */
    @GetMapping("/unsafe/api-keys")
    public String unsafeGetApiKeys(@RequestParam String username) {
        // 危险实践：未验证用户身份就返回敏感API密钥
        return "{'apiKey': 'sensitive-api-key-value', 'username': '" + username + "'}";
    }

    /**
     * 不安全示例：用户角色修改接口（权限控制缺失）
     * 漏洞点：
     * 1. 允许任意用户修改任意用户的角色，未验证操作权限
     * 2. 没有对角色修改操作进行限制和审计
     * 攻击示例：
     * 攻击者将自己的角色修改为管理员
     * POST /security-example/idor/unsafe/update-role?userId=3&newRole=ADMIN
     * 修复建议：
     * 1. 严格限制角色修改权限，仅允许高权限管理员操作
     * 2. 对角色变更进行多级审批和日志记录
     * 3. 禁止直接通过API参数修改为最高权限角色
     */
    @PostMapping("/unsafe/update-role")
    public String unsafeUpdateUserRole(@RequestParam Integer userId, @RequestParam String newRole) {
        // 危险实践：未验证操作者是否有修改角色的权限
        return "Updated role to " + newRole + " for user: " + userId;
    }

    /**
     * 不安全示例：系统日志查询接口（权限校验缺失）
     * 漏洞点：
     * 1. 未验证用户是否有查看系统日志的权限
     * 2. 允许任意用户访问系统级敏感信息
     * 攻击示例：
     * 普通用户查询系统日志，获取其他用户操作记录或系统配置信息
     * GET /security-example/idor/unsafe/system-logs?date=2023-10-01
     * 修复建议：
     * 1. 系统日志应仅对管理员开放
     * 2. 实施基于角色的访问控制(RBAC)
     * 3. 限制日志查询的时间范围和详细程度
     */
    @GetMapping("/unsafe/system-logs")
    public String unsafeGetSystemLogs(@RequestParam String date) {
        // 危险实践：未验证用户是否有权限查看系统日志
        return "System logs for date: " + date;
    }

    /**
     * 不安全示例：个人消息查询接口（未验证访问权限）
     * 漏洞点：
     * 1. 直接使用用户提供的userId查询消息，未验证权限
     * 2. 私人消息属于高度敏感信息，缺乏保护
     * 攻击示例：
     * 攻击者修改userId参数，查看其他用户的私人消息
     * GET /security-example/idor/unsafe/user-messages?userId=1
     * 修复建议：
     * 1. 消息查询应基于当前登录用户ID，而非用户输入
     * 2. 对消息内容进行加密存储
     * 3. 敏感消息添加访问提醒
     */
    @GetMapping("/unsafe/user-messages")
    public String unsafeGetUserMessages(@RequestParam Integer userId) {
        // 危险实践：未验证用户是否有权查看目标用户的消息
        return "Messages for user: " + userId;
    }

    /**
     * 安全示例：用户信息查询（带权限验证）
     * 修复说明：
     * 1. 从当前会话获取登录用户ID，而非完全依赖请求参数
     * 2. 验证请求的目标用户ID是否与登录用户一致
     * 3. 对管理员角色的跨用户访问添加额外权限检查
     */
    @GetMapping("/safe/user-profile")
    public String safeGetUserProfile(@RequestParam Integer targetUserId) {
        // 安全实践：从会话中获取当前登录用户信息（实际应用中从SecurityContext或Token中获取）
        Integer currentUserId = getCurrentLoggedInUserId();
        String currentUserRole = getCurrentUserRole();

        // 权限验证：普通用户只能查看自己的信息，管理员需额外权限检查
        if (!currentUserId.equals(targetUserId) && !"ADMIN".equals(currentUserRole)) {
            return "{'error': 'Access denied: You do not have permission to view this user profile'}";
        }

        // 管理员操作审计（实际应用中应记录日志）
        if ("ADMIN".equals(currentUserRole) && !currentUserId.equals(targetUserId)) {
            logAdminAccess(currentUserId, targetUserId, "view profile");
        }

        // 正常查询逻辑
        if (targetUserId == 1) {
            return "{'userId': 1, 'username': 'admin', 'email': 'admin@example.com', 'phone': '138****8000'}";
        } else if (targetUserId == 2) {
            return "{'userId': 2, 'username': 'test', 'email': 'test@example.com', 'phone': '139****9000'}";
        }
        return "{'error': 'User not found'}";
    }

    // 以下为辅助方法，实际应用中会有相应实现
    private Integer getCurrentLoggedInUserId() {
        // 示例：从会话获取当前登录用户ID
        return 2; // 假设当前登录用户ID为2（普通用户）
    }

    private String getCurrentUserRole() {
        // 示例：获取当前用户角色
        return "USER"; // 普通用户角色
    }

    private void logAdminAccess(Integer adminId, Integer targetUserId, String action) {
        // 示例：记录管理员操作日志
        System.out.println("Admin " + adminId + " performed action: " + action + " on user " + targetUserId);
    }
}
