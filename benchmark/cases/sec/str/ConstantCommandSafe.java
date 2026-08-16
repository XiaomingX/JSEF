/*
 * JSEF Benchmark — FP 混淆型安全样本（CWE-78, 难度 L3）
 *
 * 样本 3：常量拼接 safe — 命令字符串完全由常量组成，无不可信变量。
 *   Runtime.exec 调用看似危险，但命令文本中没有任何污点，无法被注入。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

import java.io.IOException;

public class ConstantCommandSafe {

    /**
     * 安全入口：命令由常量字面量拼接，source 标注为 "constant (no taint)"。
     */
    static void safe() throws IOException {
        String cmd = "ls" + " -l" + " /tmp";
        // [CHECKPOINT id=JSEF-FP-004 cwe=78 level=L3 source=constant (no taint) sink=Runtime.getRuntime().exec expect=SAFE]
        Runtime.getRuntime().exec(cmd);
    }
}
