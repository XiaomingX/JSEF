package com.jsef.benchmark.vuln.multivuln;

/**
 * JSEF-Benchmark 样本族 B — 多漏洞组合链：第一环 · 信息泄露（CWE-532，L5）
 *
 * 难度：L5（多漏洞类型串成完整链的第一环）
 *
 * 角色：审计日志保险库。把请求方传入的 userId 直接写进日志，未脱敏。
 * 单独看：一条"记录访问日志"的常规操作；但它是整条多漏洞链的起点——
 * 攻击者据此泄露出的 userId 作为第二环（ProfileController 越权）的输入。
 *
 * 本文件设子 checkpoint {@code JSEF-OS-004A}（CWE-532 信息泄露的独立判定点），
 * 与主链 id {@code JSEF-OS-004}（第二环越权 sink）成对出现、归属同一目标。
 *
 * 修复要点：日志脱敏（仅记录掩码后的 id），不写原始 userId。
 *
 * 安全底线：仅 localhost 演示，不写真实攻击载荷。
 */
public class AuditLogVault {

    /**
     * 危险入口：把 userId 原样写入日志（信息泄露，第一环 sink）。
     *
     * @param userId 不可信请求携带的（或可被诱导的）用户标识
     */
    public String logAccess(String userId) {
        // 第一环 checkpoint：userId 被原样写入日志（CWE-532）
        // [CHECKPOINT id=JSEF-OS-004A cwe=532 level=L5 source=user id in access request sink=log raw userId expect=VULN trace=benchmark/cases/vuln/multivuln/ProfileController.java:51,benchmark/cases/vuln/multivuln/ProfileController.java:55]
        System.out.println("[audit] access by user=" + userId); // 信息泄露：原始 id 入日志
        return userId;
    }
}
