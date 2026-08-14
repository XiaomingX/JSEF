package com.jsef.benchmark.sec;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark L2 — TaintMultiHop 安全对照（SAFE 混淆样本）
 *
 * 安全做法：在中间变量阶段即做白名单净化，sink 仅接收受控常量/白名单命令。
 * 多跳链路存在，但污点在落入 sink 前已被净化（常量命令字面值）。
 * 用于计算 TN / FP。
 *
 * CWE-78 OS Command Injection。
 */
public class TaintMultiHopSafe {

    private static final List<String> ALLOWLIST = Arrays.asList("echo", "ping", "hostname");

    public void runCommand(String userInput) throws IOException {
        String a = userInput;
        String b = a + " ; echo localhost";
        String c = b.trim();
        // 净化：解析命令名并校验白名单，仅用常量命令字面值
        String name = c.split("\\s+")[0];
        if (!ALLOWLIST.contains(name)) {
            throw new IllegalArgumentException("command not allowed: " + name);
        }
        // [CHECKPOINT id=JSEF-TP-002S cwe=78 level=L2 source=userInput sink=Runtime.getRuntime().exec expect=SAFE]
        Process p = Runtime.getRuntime().exec(new String[]{"echo", "localhost-demo"});
    }

    public static void main(String[] args) throws IOException {
        new TaintMultiHopSafe().runCommand("echo hi");
    }
}
