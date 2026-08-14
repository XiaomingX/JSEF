package com.jsef.benchmark.sec;

import java.util.Set;

/**
 * JSEF-Benchmark Phase5-A — Partial Fix 的真正修复版（CWE-78 命令注入，难度 L3）
 *
 * 与 CmdPartialAllowlist 对照：命令名白名单 + 参数白名单双校验，
 * 且改用数组形式 exec（不经 shell 解释），参数无法追加命令。
 * 因此是真正的 SAFE，用于计算 TN / 误报（FP）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class CmdPartialAllowlistSafe {

    static final Set<String> ALLOWED_COMMANDS = Set.of("ls", "cat");
    // 参数白名单：仅允许简单文件名（字母数字 . _ -）
    static final java.util.regex.Pattern SAFE_ARG = java.util.regex.Pattern.compile("[a-zA-Z0-9._-]+");

    /**
     * 安全入口：命令名白名单 + 参数白名单 + 数组参数化（无 shell）。
     */
    static Process run(String cmdName, String arg) throws Exception {
        if (!ALLOWED_COMMANDS.contains(cmdName)) {
            throw new IllegalArgumentException("command not allowed: " + cmdName);
        }
        if (!SAFE_ARG.matcher(arg).matches()) {
            throw new IllegalArgumentException("invalid argument: " + arg);
        }
        // [CHECKPOINT id=JSEF-PF-002S cwe=78 level=L3 source=arg (whitelist-checked) sink=Runtime.getRuntime().exec expect=SAFE]
        return Runtime.getRuntime().exec(new String[]{cmdName, arg}); // 数组形式，无 shell，无法注入
    }
}
