/*
 * JSEF Benchmark 真假混淆样本 — 命令注入（B5，CWE-78）
 * VULN 版：exec(userInput) 直接执行用户可控命令。
 * 文件头说明：独立 benchmark 源文件，使用模拟 Runtime.exec 表达 sink，不强求编译。
 */
public class ConfusionCmdSanitized {

    static Process exec(String cmd) throws Exception {
        // 模拟：Runtime.getRuntime().exec
        return null; // SINK（语义）
    }

    /**
     * 危险入口：用户可控命令字符串直接交给 exec（经 shell 解析）。
     */
    static void unsafe(String userInput) throws Exception { // source：不可信用户输入
        // [CHECKPOINT id=JSEF-CONF-CMD-001 cwe=78 level=L1 source=user input sink=Runtime.getRuntime().exec expect=VULN]
        exec(userInput); // 用户控制完整命令，命令注入
    }
}
