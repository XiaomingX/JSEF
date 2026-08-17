package com.jsef.benchmark.vuln.logic;

/*
 * JSEF-Benchmark L2 — 服务端信任客户端声明的角色字段（CWE-602）
 *
 * 验收点：服务端从请求参数 / 隐藏域 / 自定义请求头直接读取前端传入的 `role`
 * 字段，并据此建立会话或授权，而非以服务端会话主体（已认证用户）的角色为准。
 * 攻击者可将 role 篡改为 admin 等特权角色，实现权限提升。
 *
 * 教学占位：RoleControllerStub 从请求参数取 role 调用模拟授权 sink grantRole()。
 * 不 import 任何真实 Web 框架；仅用占位方法模拟。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 *
 * 修复要点（对照 ClientTrustedRoleSafe.java）：以服务端会话主体角色为准，
 * 忽略前端传入的角色字段。
 */
public class ClientTrustedRoleVuln {

    /**
     * 教学占位：模拟一个从请求取角色并建会话的控制器方法。
     *
     * @param role 前端传入的 role（请求参数/隐藏域/请求头），不可信
     */
    public void login(String username, String role) {
        // 危险点：直接信任客户端声明的 role 建立授权
        // [CHECKPOINT id=JSEF-CTR-001 cwe=602 level=L2 source=request param role sink=grantRole (trusts client-supplied role) expect=VULN]
        grantRole(username, role);   // 攻击者传 role=admin 即提权
    }

    // 抽象 sink：语义等价 session.setAttribute("role", role) / 授权。仅 localhost 演示。
    static void grantRole(String username, String role) {
        System.out.println("[authz] grant role=" + role + " to " + username);
    }

    public static void main(String[] args) {
        new ClientTrustedRoleVuln().login("attacker", "admin");
    }
}
