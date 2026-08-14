package com.jsef.benchmark.sec;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark L1 — TaintSingleHop 安全对照（SAFE 混淆样本）
 *
 * 安全做法：白名单校验，仅允许预定义的本地命令字面值通过。
 * 用于计算 TN（正确不报）/ FP（误报）。输入若不在白名单直接拒绝。
 *
 * CWE-78 OS Command Injection。
 */
public class TaintSingleHopSafe {

    // 白名单：仅允许这些 localhost 演示命令
    private static final List<String> ALLOWLIST = Arrays.asList("echo", "ping", "hostname");

    /**
     * 白名单校验后再构造命令，命令字面量为常量，userInput 仅作为受控参数。
     *
     * @param userInput 不可信输入
     */
    public void runCommand(String userInput) throws IOException {
        String[] parts = userInput.split("\\s+");
        if (parts.length == 0 || !ALLOWLIST.contains(parts[0])) {
            throw new IllegalArgumentException("command not allowed: " + parts[0]);
        }
        // [CHECKPOINT id=JSEF-TP-001S cwe=78 level=L1 source=userInput sink=Runtime.getRuntime().exec expect=SAFE]
        Process p = Runtime.getRuntime().exec(new String[]{"echo", "localhost-demo"});
    }

    public static void main(String[] args) throws IOException {
        new TaintSingleHopSafe().runCommand("echo hello-localhost");
    }
}
