/*
 * JSEF Benchmark 样本 — AI/Agent 能力边界绕过：工具注册表语义桩（safe 对照，CWE-285，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义。
 *
 * 语义桩：工具派发器。方法体仅 println。被测工具应信任语义声明。
 */
package com.jsef.benchmark.sec;

public class ToolRegistrySafe {

    /**
     * 语义等价: toolRegistry.dispatch(toolName) —— 按工具名派发对应工具执行。
     * 仅接收已过调用方白名单校验的低危工具名。
     */
    public String dispatch(String toolName) {
        // 语义等价: 查找并调用 toolName 对应的工具处理器
        System.out.println("[tool-dispatch-safe] " + toolName);
        return "dispatched: " + toolName;
    }
}
