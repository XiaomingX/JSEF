// [VULN]（安全对照样本，expect=SAFE）
package com.jsef.benchmark.sec.mspdistractor;

import java.io.IOException;

/**
 * JSEF-Benchmark — 多步规划 P4 安全对照 (难度 L4, CWE-78, expect=SAFE)
 *
 * 修复思路（对照 vuln 版本 DistractorForkCmd）：
 *   统一校验点拦截危险命令，真 sink 仅在白名单内可达；分叉与假 sink 语义不变。
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class DistractorForkCmd_Safe {

    private static final String[] ALLOWED = {"echo", "ls", "date"};

    public String handle(String cmd) throws IOException {
        // [CHECKPOINT id=JSEF-MSP-005S cwe=78 level=L4 source=@RequestParam cmd sink=allowlist reject expect=SAFE]
        boolean ok = false;
        for (String a : ALLOWED) {
            if (cmd.startsWith(a)) { ok = true; break; }
        }
        if (!ok) {
            return "blocked"; // 不可信命令被拒，无法到达 sink
        }
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
        return "pid=" + p.pid();
    }
}
