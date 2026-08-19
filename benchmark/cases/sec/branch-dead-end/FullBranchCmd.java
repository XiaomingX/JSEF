package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L3 — FullBranchCmd 安全对照（两条分支均消毒截断）
 *
 * 安全做法：与 AdminBranchCmd 相同的 if/else 结构，但两条分支（isAdmin 与 else）
 * 都先调用 sanitize 完整消毒再 exec——两条路径均被截断，无命令注入。用于计算
 * TN / FP（防“看到 sanitize 就报 SAFE”的误报，同时也防止“看到 sink 就报 VULN”）。
 *
 * CWE-78 (OS Command Injection)。安全底线：仅 localhost 演示语义。
 */
public class FullBranchCmd {

    /**
     * 两条分支都消毒后执行。
     *
     * @param isAdmin 是否管理员
     * @param cmd     用户可控命令
     */
    public void exec(boolean isAdmin, String cmd) {
        if (isAdmin) {
            cmd = sanitize(cmd);            // isAdmin 分支：消毒截断
            run(cmd);                       // 安全 sink
        } else {
            cmd = sanitize(cmd);            // else 分支：同样消毒截断
            // [CHECKPOINT id=JSEF-DEAD-001S cwe=78 level=L3 source=cmd sink=Runtime.getRuntime().exec (sanitized both branches) expect=SAFE]
            run(cmd);                       // 消毒后安全 sink → SAFE
        }
    }

    // 消毒：去除命令拼接元字符
    static String sanitize(String s) {
        return s.replace(";", "").replace("&", "").replace("|", "");
    }

    // 抽象安全 sink：语义等价 Runtime.getRuntime().exec(sanitizedCmd)
    static void run(String cmd) {
        System.out.println("[cmd-exec-safe] " + cmd);
    }

    public static void main(String[] args) {
        new FullBranchCmd().exec(false, "ls; rm -rf /");
    }
}
