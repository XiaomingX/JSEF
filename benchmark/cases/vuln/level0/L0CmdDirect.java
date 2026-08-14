package com.jsef.benchmark.vuln;

import java.io.IOException;

/**
 * JSEF-Benchmark L0 — 基线（命令注入，单跳直连）
 *
 * 难度：L0（基线）。source 直接传入 sink，无中间变量。
 * 用于校准 TP 基线与定位精度（CAP-03 入门级）。
 *
 * CWE-78 OS Command Injection。
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class L0CmdDirect {

    /**
     * 单跳：不可信入参直接作为命令执行（sink）。
     *
     * @param userInput 不可信输入（类比 @RequestParam command）
     */
    public void run(String userInput) throws IOException {
        // [CHECKPOINT id=JSEF-L0-CMD-001 cwe=78 level=L0 source=userInput sink=Runtime.getRuntime().exec expect=VULN]
        Process p = Runtime.getRuntime().exec(userInput);
    }

    public static void main(String[] args) throws IOException {
        new L0CmdDirect().run("echo hello-localhost");
    }
}
