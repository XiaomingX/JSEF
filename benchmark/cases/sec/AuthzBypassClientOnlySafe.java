/*
 * JSEF Benchmark 样本 — 认证保护修复：后端在每次敏感操作前真实重校验会话/凭据（CWE-522，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 修复要点：不信任客户端提交的"已认证"标记，操作前从 HttpSession 读取服务端
 * 认证态并重校验，缺失会话则拒绝进入敏感操作。
 */
package com.jsef.benchmark.sec;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

public class AuthzBypassClientOnlySafe {

    /**
     * 语义桩：等价于后端敏感管理操作。此处真实实现：调用者身份由服务端会话提供。
     * 语义等价: adminOperation()
     */
    void adminOperation(String operator) {
        System.out.println("[admin-op] operator=" + operator); // 语义等价：执行管理员敏感操作
    }

    /**
     * 安全：忽略客户端标记，操作前从服务端会话重校验认证态；无会话则拒绝。
     */
    public String openAdmin(HttpServletRequest request) {
        HttpSession session = request.getSession(false); // 不创建新会话
        // [CHECKPOINT id=JSEF-AUTH-001S cwe=522 level=L4 source=request sink=server-side session re-validation before adminOperation() expect=SAFE]
        if (session == null || session.getAttribute("authenticatedUser") == null) {
            return "forbidden"; // 后端拒绝：无服务端认证态
        }
        adminOperation((String) session.getAttribute("authenticatedUser")); // 身份来自服务端会话
        return "processed";
    }
}
