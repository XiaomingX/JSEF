package com.jsef.benchmark.vuln;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * JSEF-Benchmark L3 — 间接污点传播（Map 传递，命令注入）
 *
 * 难度：L3（间接污点）。source 存入 Map<String,Object> 后以 key 取出，经字段/方法传入 sink。
 * 污点不直接通过变量赋值链追踪，而是经容器存取——模拟 fastjson @type 风格的反序列化路由。
 * 纯语法工具很难识别"Map.get(key)"取出的即是不受信数据（CAP-05）。
 *
 * CWE-78 OS Command Injection。
 */
public class TaintIndirectMap {

    /**
     * 间接污点：userInput 放入 Map，以 "cmd" 取出后进入 sink。
     *
     * @param userInput 不可信输入
     */
    public void runCommand(String userInput) throws IOException {
        Map<String, Object> ctx = new HashMap<>();
        ctx.put("cmd", userInput);                 // source 存入 Map（@type 风格路由）

        Object field = ctx.get("cmd");             // 以 key 取出，污点不直接变量赋值
        String resolved = String.valueOf(field);

        // [CHECKPOINT id=JSEF-TP-003 cwe=78 level=L3 source=Map.get(cmd) sink=Runtime.getRuntime().exec expect=VULN]
        Process p = Runtime.getRuntime().exec(resolved);
    }

    public static void main(String[] args) throws IOException {
        new TaintIndirectMap().runCommand("echo localhost");
    }
}
