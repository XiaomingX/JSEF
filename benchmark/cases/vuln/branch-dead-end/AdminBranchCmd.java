package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L3 — 活分支消毒截断（if/else，仅一分支消毒）
 *
 * 难度：L3（同方法内条件分支的路径可达性判定）。`if (isAdmin)` 是一条活分支（可达），
 * 该分支上对 cmd 做了完整消毒（去掉 ;|&），所以这条分支确实到不了 sink；但 `else`
 * 分支把原 cmd 原样拼入 exec，是真正可达的 sink。被测对象若只看到“存在 sanitize 调用”
 * 就报 SAFE，会漏报 else 分支的真实命令注入（过早下结论）；反之若只看到“有 exec sink”
 * 就对整行报 VULN，会误报 isAdmin 分支（FP）。
 *
 * 与 DeadBranchSanitizeVuln（JSEF-DBS-001）方向相反：DBS 的净化在恒假死分支、净化从不
 * 生效、sink 反而可达；本样本的净化在可达的活分支、该分支 sink 确实不可达。与
 * confusion/case-bypass（假消毒/名字混淆）也不同：这里的消毒在 isAdmin 分支真实生效。
 *
 * CWE-78 (OS Command Injection)。安全底线：仅 localhost 演示语义。
 *
 * 修复要点（对照 FullBranchCmd.java）：两条分支都必须消毒/参数化——else 分支同样用
 * 白名单或固定程序名，不把原 cmd 拼入 exec。
 */
public class AdminBranchCmd {

    /**
     * 根据管理员状态分派：管理员分支消毒，普通分支原样拼入命令。
     *
     * @param isAdmin 是否管理员
     * @param cmd     用户可控命令
     */
    public void exec(boolean isAdmin, String cmd) {
        if (isAdmin) {
            cmd = sanitize(cmd);            // 活分支：完整消毒，该分支不可达 sink（SAFE 路径）
            run(cmd);
        } else {
            // [CHECKPOINT id=JSEF-DEAD-001 cwe=78 level=L3 source=cmd sink=Runtime.getRuntime().exec (else branch, unsanitized) expect=VULN]
            run(cmd);                       // else 活分支：原 cmd 直连 sink → VULN
        }
    }

    // 消毒：去除命令拼接元字符（语义上阻断多命令注入）
    static String sanitize(String s) {
        return s.replace(";", "").replace("&", "").replace("|", "");
    }

    // 抽象 sink：语义等价 Runtime.getRuntime().exec(cmd)，仅 localhost 打印
    static void run(String cmd) {
        System.out.println("[cmd-exec] " + cmd);
    }

    public static void main(String[] args) {
        new AdminBranchCmd().exec(false, "ls; rm -rf /");
    }
}
