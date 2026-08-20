/*
 * JSEF Benchmark 样本 — 认证保护不足：凭据/角色校验仅发生在客户端（信任边界缺失，CWE-522，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"信任边界"——前端校验通过后传入一个"已认证"标记/用户名，
 * 后端直接信任该标记而不查会话、不重校验凭据/角色，随即进入 admin 敏感操作。
 * 静态分析需在授权决策处识别"客户端可控的已认证标记被直接信任进入敏感操作"这一缺失重校验缺陷。
 */
package com.jsef.benchmark.vuln;

import jakarta.servlet.http.HttpServletRequest;

public class AuthzBypassClientOnlyVuln {

    /**
     * 语义桩：等价于后端敏感管理操作（读取/执行管理员才可访问的动作）。
     * 语义等价: adminOperation() —— 仅当调用者身份被后端真实验证时才允许。
     */
    void adminOperation(String operator) {
        System.out.println("[admin-op] operator=" + operator); // 语义等价：执行管理员敏感操作
    }

    /**
     * 危险：后端不重校验会话/凭据，直接信任客户端提交的"已认证"标记。
     * source：客户端可控的已认证标记（HTTP 头/参数），由前端校验后透传。
     * sink：未经后端重校验直接进入 admin 敏感操作。
     */
    public String openAdmin(HttpServletRequest request) {
        // source：客户端可控标记，客户端校验通过后由前端透传（攻击者可伪造）
        String authenticatedUser = request.getHeader("X-Authenticated-User");
        // 危险：信任客户端标记，未查 HttpSession、未重校验密码/角色即进入授权分支
        // [CHECKPOINT id=JSEF-AUTH-001 cwe=522 level=L4 source=client-controlled auth marker (X-Authenticated-User) sink=adminOperation() without backend re-validation expect=VULN]
        if (authenticatedUser != null) {
            adminOperation(authenticatedUser); // 直接进入 admin 敏感操作（凭据仅前端校验）
        }
        return "processed";
    }
}
