package com.jsef.benchmark.vuln;

import java.util.Set;

/**
 * JSEF-Benchmark Phase5-A — Partial Fix（部分修复陷阱，CWE-78 命令注入，难度 L3）
 *
 * 混淆点（为什么容易被误判）：
 * 方法对"命令名"做了白名单校验，看起来很规范：只允许执行 "ls" / "cat"。
 * 但命令的"参数"仍然直接拼接进命令行字符串，再交给 shell 执行。
 * 即使命令名受控，参数里仍可注入额外命令（如 "x; rm -rf /"）。
 * 弱被测对象见到 allowlist 校验就判定"已防护"，从而漏报（FN）。
 * 它实际仍是 VULN。
 *
 * 目的：与 SQL 部分修复样本呼应，专测"只见首道守卫即收手"的激进型被测对象。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class CmdPartialAllowlist {

    // 仅允许执行的命令名白名单（受控常量）
    static final Set<String> ALLOWED_COMMANDS = Set.of("ls", "cat");

    /**
     * 危险入口：命令名白名单校验，但参数仍拼接 → 仍命令注入。
     */
    static Process run(String cmdName, String arg) throws Exception {
        if (!ALLOWED_COMMANDS.contains(cmdName)) {
            throw new IllegalArgumentException("command not allowed: " + cmdName);
        }
        // 参数未校验，直接拼入 shell 命令行
        String shellLine = cmdName + " " + arg;
        // [CHECKPOINT id=JSEF-PF-002 cwe=78 level=L3 source=arg (user-controlled) sink=Runtime.getRuntime().exec expect=VULN]
        return Runtime.getRuntime().exec(new String[]{"sh", "-c", shellLine}); // 参数可注入额外命令
    }
}
