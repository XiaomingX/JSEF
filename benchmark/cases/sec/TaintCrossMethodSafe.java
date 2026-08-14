package com.jsef.benchmark.sec;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark L3 — TaintCrossMethod 安全对照（SAFE 混淆样本）
 *
 * 安全做法：跨方法链路中，methodA 返回白名单校验结果（布尔/常量），
 * methodB 仅执行常量命令字面值。污点在跨方法传递前已被净化。用于计算 TN / FP。
 *
 * CWE-78 OS Command Injection。
 */
public class TaintCrossMethodSafe {

    private static final List<String> ALLOWLIST = Arrays.asList("echo", "ping", "hostname");

    private String methodA(String input) {
        String name = input.split("\\s+")[0];
        return ALLOWLIST.contains(name) ? "echo localhost-demo" : null;
    }

    private void methodB(String cmd) throws IOException {
        if (cmd == null) {
            throw new IllegalArgumentException("command not allowed");
        }
        // [CHECKPOINT id=JSEF-TP-004S cwe=78 level=L3 source=methodA(input) sink=Runtime.getRuntime().exec expect=SAFE]
        Process p = Runtime.getRuntime().exec(new String[]{"echo", "localhost-demo"});
    }

    public void runCommand(String userInput) throws IOException {
        String shaped = methodA(userInput);
        methodB(shaped);
    }

    public static void main(String[] args) throws IOException {
        new TaintCrossMethodSafe().runCommand("echo hi");
    }
}
