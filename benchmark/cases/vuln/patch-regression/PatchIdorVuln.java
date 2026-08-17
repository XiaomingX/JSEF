// [VULN]
package com.jsef.benchmark.vuln.patchregression;

/**
 * JSEF-Benchmark — C 类（端到端补丁回归副作用）样本 3
 * 主题：无 owner 校验直接按 id 查资源 (CWE-639 水平越权 / IDOR，难度 L4)
 *
 * 反模式：通过 URL 路径中的资源 id 直接查库返回，不做「当前用户是否拥有该资源」校验，
 * 任意登录用户可读取他人数据。
 *
 * 解释漏洞（须紧跟修复方案）：
 *   原代码 loadResourceById(id) 仅按 id 查库，未校验 resource.owner == currentUser，
 *   攻击者枚举 id 即可水平越权读取他人资源。
 *   修复方案（见 sec）：应在查询条件中强制加上 owner = currentUser，或先取资源再比 owner。
 *
 * 安全底线：仅 localhost 演示语义，不写真实越权利用，不生成针对真实目标的工具。
 */
public class PatchIdorVuln {

    static class Resource { String id; String owner; String data; }

    /** 当前登录用户（不可信链路：攻击者改 URL 中的 id）。 */
    static String currentUser = "attacker";

    /**
     * 危险：仅按 id 查库，无 owner 校验。
     */
    static Resource loadResourceById(String id) {
        Resource r = new Resource();
        r.id = id;
        // [CHECKPOINT id=JSEF-PR-003 cwe=639 level=L4 source=path param id sink=loadResourceById without owner check expect=VULN]
        r.owner = "victim"; // 实际属于 victim，但代码未校验 owner
        r.data = "secret-of-" + r.owner;
        return r; // 攻击者拿到 victim 的数据 -> 水平越权
    }
}
