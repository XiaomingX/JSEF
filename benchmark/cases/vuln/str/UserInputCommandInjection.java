/*
 * JSEF Benchmark — FP 混淆型安全样本的对照 vuln（CWE-78, 难度 L3）
 *
 * 对照样本：命令字符串由不可信用户输入拼接，可注入额外命令。
 * 与 ConstantCommandSafe 的纯常量命令形成 vuln/safe 对。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.vuln;

import java.io.IOException;

public class UserInputCommandInjection {

    /**
     * 危险入口：命令由 userInput 拼接，可注入（如 "; rm -rf /"）。
     * @param userInput 不可信用户输入
     */
    static void unsafe(String userInput) throws IOException {
        String cmd = "ping -c 1 " + userInput;
        // [CHECKPOINT id=JSEF-FP-004V cwe=78 level=L3 source=userInput sink=Runtime.getRuntime().exec expect=VULN]
        Runtime.getRuntime().exec(cmd);
    }
}
