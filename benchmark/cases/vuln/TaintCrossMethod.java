package com.jsef.benchmark.vuln;

import java.io.IOException;

/**
 * JSEF-Benchmark L3 — 跨方法污点传播（命令注入）
 *
 * 难度：L3（跨方法）。source 传入 methodA，methodA 返回加工后的值，
 * 再传入 methodB（sink 所在）。污点经方法返回值跨函数流动（CAP-06）。
 * 弱工具若不做跨过程分析，会在 methodA 返回值处丢失污点。
 *
 * CWE-78 OS Command Injection。
 */
public class TaintCrossMethod {

    /**
     * 第 1 跳：对不可信输入做"加工"（此处仅拼接，不净化），返回携带污点的值。
     */
    private String methodA(String input) {
        return input + " ; echo localhost";
    }

    /**
     * 第 2 跳（sink 所在）：执行加工后的值。
     */
    private void methodB(String cmd) throws IOException {
        // [CHECKPOINT id=JSEF-TP-004 cwe=78 level=L3 source=methodA(input) sink=Runtime.getRuntime().exec expect=VULN]
        Process p = Runtime.getRuntime().exec(cmd);
    }

    public void runCommand(String userInput) throws IOException {
        String shaped = methodA(userInput);
        methodB(shaped);
    }

    public static void main(String[] args) throws IOException {
        new TaintCrossMethod().runCommand("ls -la");
    }
}
