package com.jsef.benchmark.sec;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JSEF-Benchmark L3 — TaintIndirectMap 安全对照（SAFE 混淆样本）
 *
 * 安全做法：从 Map 取出后做白名单校验，sink 仅接收常量命令字面值。
 * 间接污点链路存在，但在取出后已被净化。用于计算 TN / FP。
 *
 * CWE-78 OS Command Injection。
 */
public class TaintIndirectMapSafe {

    private static final List<String> ALLOWLIST = Arrays.asList("echo", "ping", "hostname");

    public void runCommand(String userInput) throws IOException {
        Map<String, Object> ctx = new HashMap<>();
        ctx.put("cmd", userInput);

        Object field = ctx.get("cmd");
        String resolved = String.valueOf(field);

        String name = resolved.split("\\s+")[0];
        if (!ALLOWLIST.contains(name)) {
            throw new IllegalArgumentException("command not allowed: " + name);
        }
        // [CHECKPOINT id=JSEF-TP-003S cwe=78 level=L3 source=Map.get(cmd) sink=Runtime.getRuntime().exec expect=SAFE]
        Process p = Runtime.getRuntime().exec(new String[]{"echo", "localhost-demo"});
    }

    public static void main(String[] args) throws IOException {
        new TaintIndirectMapSafe().runCommand("echo hi");
    }
}
