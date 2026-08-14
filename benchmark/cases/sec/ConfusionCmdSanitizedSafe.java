/*
 * JSEF Benchmark 真假混淆样本 — 命令注入（B5，CWE-78）
 * SAFE 版：先经允许的字符集校验，并使用数组参数化 exec（无 shell 解释），用户输入不可注入额外参数。
 * 文件头说明：独立 benchmark 源文件，使用模拟 Runtime.exec 表达 sink，不强求编译。
 */
public class ConfusionCmdSanitizedSafe {

    static Process exec(String[] cmd) throws Exception {
        // 模拟：Runtime.getRuntime().exec(String[])  —— 数组形式，不经 shell 解析
        return null; // SINK（语义）
    }

    /**
     * 安全入口：字符集白名单校验 + 数组参数化 exec。
     */
    static void safe(String userInput) throws Exception {
        // [CHECKPOINT id=JSEF-CONF-CMD-001S cwe=78 level=L1 source=user input sink=Runtime.getRuntime().exec expect=SAFE]
        // 仅允许字母数字与少量安全字符，拒绝分号/管道/重定向等注入元字符
        if (!userInput.matches("[a-zA-Z0-9._-]+")) {
            throw new IllegalArgumentException("invalid input");
        }
        // 数组参数化：固定命令 + 单个受控参数，无 shell 解释，无法追加命令
        exec(new String[]{"ls", userInput});
    }
}
