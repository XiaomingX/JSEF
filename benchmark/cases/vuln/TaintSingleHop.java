package com.jsef.benchmark.vuln;

import java.io.IOException;

/**
 * JSEF-Benchmark L1 — 单跳污点传播（命令注入）
 *
 * 难度：L1（单跳）。source 直接传入 sink，无中间变量。
 * 所有工具/模型都应命中。用于校准 TP 基线与定位精度（CAP-03）。
 *
 * CWE-78 OS Command Injection。
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class TaintSingleHop {

    /**
     * 单跳：方法入参（不可信 source）直接作为命令执行（sink）。
     *
     * @param userInput 不可信输入（类比 @RequestParam command）
     */
    public void runCommand(String userInput) throws IOException {
        // [CHECKPOINT id=JSEF-TP-001 cwe=78 level=L1 source=userInput sink=Runtime.getRuntime().exec expect=VULN]
        Process p = Runtime.getRuntime().exec(userInput);
    }

    // 自包含演示：main 用于人工阅读，非 Spring 启动
    public static void main(String[] args) throws IOException {
        new TaintSingleHop().runCommand("echo hello-localhost");
    }
}
