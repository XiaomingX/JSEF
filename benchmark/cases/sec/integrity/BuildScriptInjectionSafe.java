package com.jsef.benchmark.sec.integrity;

import java.util.Arrays;
import java.util.List;

/**
 * JSEF Benchmark — A08 安全对照（CWE-506，L4）
 *
 * SAFE：对分支名做白名单校验并使用参数化执行（不拼接 shell）。
 */
public class BuildScriptInjectionSafe {

    private static final List<String> ALLOWED = Arrays.asList("main", "release", "develop");

    /**
     * SAFE：白名单校验 + 参数化执行。
     */
    public static void runBuild(String branchName) throws Exception {
        // source：不可信的 branch/pr 参数
        if (!ALLOWED.contains(branchName)) {
            throw new IllegalArgumentException("非法分支名: " + branchName);
        }
        // [CHECKPOINT id=JSEF-A08-003S cwe=506 level=L4 source=untrusted branch/pr param sink=ProcessBuilder (whitelist + no concat) expect=SAFE]
        new ProcessBuilder("git", "checkout", branchName).inheritIO().start();
    }
}
