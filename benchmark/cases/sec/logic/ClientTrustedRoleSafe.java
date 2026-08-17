package com.jsef.benchmark.sec.logic;

/*
 * JSEF-Benchmark L2 — 服务端信任客户端声明角色 安全对照（CWE-602）
 *
 * 修复：忽略前端传入的 role 字段，以服务端会话主体（已认证用户）的角色为准。
 * 即使客户端伪造 role=admin，授权仍基于服务端存储的角色。
 *
 * SAFE 侧按实现判安全：授权取自服务端会话主体，非客户端输入。
 */
public class ClientTrustedRoleSafe {

    /**
     * 教学占位：以服务端会话主体角色为准的控制器方法。
     *
     * @param role 前端传入的 role（被忽略，不可信）
     */
    public void login(String username, String role) {
        // 安全点：忽略客户端 role，使用服务端会话主体的角色
        String serverRole = lookupServerRole(username);   // 来自服务端存储/会话
        // [CHECKPOINT id=JSEF-CTR-001S cwe=602 level=L2 source=request param role sink=server session authority expect=SAFE]
        grantRole(username, serverRole);
    }

    // 模拟从服务端会话/存储查真实角色
    static String lookupServerRole(String username) {
        return "user";   // 服务端权威角色，非前端传入
    }

    // 抽象 sink：语义等价 session.setAttribute("role", role) / 授权。仅 localhost 演示。
    static void grantRole(String username, String role) {
        System.out.println("[authz] grant role=" + role + " to " + username);
    }

    public static void main(String[] args) {
        new ClientTrustedRoleSafe().login("attacker", "admin");
    }
}
