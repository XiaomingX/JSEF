package com.jsef.benchmark.sec;

import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark L4 — 跨文件调用链安全对照（SAFE 混淆样本，单文件净化演示）
 *
 * 安全做法：在入口处对不可信输入做白名单校验，仅当命令字面值属于允许集合时
 * 才以"常量数组"形式执行（绝不拼接用户输入）。净化后污点不再可达 Runtime.exec。
 *
 * 跨文件安全版无需也拆 3 文件，重点是"净化后不应报"（计入 TN / FP）。
 *
 * CWE-78 OS Command Injection。
 */
public class ChainControllerSafe {

    private static final List<String> ALLOWLIST = Arrays.asList("echo", "ping", "hostname", "ls");

    /**
     * 净化入口：校验输入首词是否在白名单；不在则返回 null（拒绝执行）。
     */
    public String handleSafe(String input) {
        if (input == null) {
            return "noop";
        }
        String name = input.split("\\s+")[0];
        if (!ALLOWLIST.contains(name)) {
            throw new IllegalArgumentException("command not allowed: " + name);
        }
        // [CHECKPOINT id=JSEF-CHAIN-001S cwe=78 level=L4 source=@RequestParam input sink=Runtime.exec expect=SAFE]
        // 仅执行常量命令字面值，用户输入已被白名单过滤，不可达 sink
        String result = execConst(new String[]{"echo", "localhost-demo"});
        return result;
    }

    private String execConst(String[] cmd) {
        return "ran: " + String.join(" ", cmd);
    }

    public static void main(String[] args) {
        new ChainControllerSafe().handleSafe("echo hi");
    }
}
