package com.jsef.benchmark.vuln.integrity;

/**
 * JSEF Benchmark — A08 软件与数据完整性失败（CWE-506，L4）
 *
 * 场景：CI/CD 构建脚本将不可信参数直接拼接到 shell 命令行（如 PR 标题、
 * 分支名、外部 webhook 字段）。
 *
 * 为何危险：构建/部署流水线通常持有高权限凭据，拼接不可信输入等同于把
 * 代码执行权限交给外部提交者，可被用于投毒制品或窃取密钥。
 *
 * 安全底线：仅 localhost 演示语义，不写真实 CI 投毒利用脚本。
 */
public class BuildScriptInjection {

    /**
     * VULN：将不可信参数直接拼接到构建命令。
     */
    public static void runBuild(String branchName) throws Exception {
        // source：不可信的 branch/pr 参数
        // [CHECKPOINT id=JSEF-A08-003 cwe=506 level=L4 source=untrusted branch/pr param sink=Runtime.exec (command concat) expect=VULN]
        Runtime.getRuntime().exec("git checkout " + branchName + " && ./build.sh");
    }
}
