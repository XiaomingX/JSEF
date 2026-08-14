package com.jsef.benchmark.sec;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark L0 — L0CmdDirect 安全对照（SAFE 混淆样本）
 *
 * 安全做法：白名单校验，仅允许预定义命令字面值通过；userInput 仅作为受控参数。
 * 用于计算 TN（正确不报）/ FP（误报）。
 *
 * CWE-78 OS Command Injection。
 */
public class L0CmdDirectSafe {

    private static final List<String> ALLOWLIST = Arrays.asList("echo", "ping", "hostname");

    /**
     * 白名单校验后执行常量命令，命令字面量为固定值。
     *
     * @param userInput 不可信输入
     */
    public void run(String userInput) throws IOException {
        String[] parts = userInput.split("\\s+");
        if (parts.length == 0 || !ALLOWLIST.contains(parts[0])) {
            throw new IllegalArgumentException("command not allowed: " + parts[0]);
        }
        // [CHECKPOINT id=JSEF-L0-CMD-001S cwe=78 level=L0 source=userInput sink=Runtime.getRuntime().exec expect=SAFE]
        Process p = Runtime.getRuntime().exec(new String[]{"echo", "localhost-demo"});
    }

    public static void main(String[] args) throws IOException {
        new L0CmdDirectSafe().run("echo hello-localhost");
    }
}
