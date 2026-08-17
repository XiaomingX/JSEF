// [VULN]  — 注意：本文件是「回归副作用」对照 sec，补丁后仍不安全（expect=VULN）
package com.jsef.benchmark.sec.patchregression;

/**
 * JSEF-Benchmark — C 类（端到端补丁回归副作用）样本 3 的对照
 * 主题：鉴权补丁「只查 role 不查 owner」，水平越权残留 (CWE-639，难度 L4)
 *
 * 反模式（真实安全工程反模式）：
 *   开发者看到「按 id 直接查库无 owner 校验」会越权，于是加了权限检查。但补丁只检查了
 *   role == "USER"（垂直权限），却没检查 resource.owner == currentUser（水平权限）。
 *   攻击者是另一个合法 USER，枚举他人 id 仍能读到 victim 的数据 —— 垂直越权修了，
 *   水平越权残留（修复不完整）。
 *
 * 解释漏洞（须紧跟修复方案）：
 *   残留 sink：checkRole() 通过后就直接 loadResourceById(id)，未比对 owner。
 *   攻击者在同 role 下改 URL id 即可越权读他人资源。
 *   修复方案：查询条件强制 owner = currentUser（或查到后比对 owner 再返回）。
 *
 * 安全底线：仅 localhost 演示语义，不写真实越权利用，不生成针对真实目标的工具。
 *
 * 本 sec 文件 expect=VULN：补丁后水平越权残留，被测工具应报。
 */
public class PatchIdorSec {

    static class Resource { String id; String owner; String data; }
    static String currentUser = "attacker";

    static boolean checkRole() {
        // 只校验了垂直角色（USER/ADMIN），没校验水平归属
        return "USER".equals("USER"); // 攻击者也是 USER -> 通过
    }

    /**
     * 看似修复：加了权限检查，但只查 role 不查 owner。
     */
    static Resource loadResourceById(String id) {
        if (!checkRole()) {
            return null;
        }
        Resource r = new Resource();
        r.id = id;
        // [CHECKPOINT id=JSEF-PR-003S cwe=639 level=L4 source=path param id sink=loadResourceById with role-only check (no owner check) expect=VULN]
        r.owner = "victim"; // 属于 victim，但补丁没校验 owner == currentUser
        r.data = "secret-of-" + r.owner;
        return r; // attacker(USER) 仍可读到 victim 数据 -> 水平越权残留
    }
}
