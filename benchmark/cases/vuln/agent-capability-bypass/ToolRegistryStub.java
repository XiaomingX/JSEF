/*
 * JSEF Benchmark 样本 — AI/Agent 能力边界绕过：工具注册表语义桩（CWE-285，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义。
 *
 * 语义桩：工具派发器。方法体仅 println，不真实执行危险操作。
 * 被测工具应信任 "// 语义等价: ..." 声明、按语义判定是否存在高危派发。
 */
package com.jsef.benchmark.vuln;

public class ToolRegistryStub {

    /**
     * 语义等价: toolRegistry.dispatch(toolName) —— 按工具名派发对应工具执行。
     * 高危工具（delete_file / grant_admin / open_url）会执行危险副作用。
     * 桩体不真实执行，仅演示语义。
     */
    public String dispatch(String toolName) {
        // 语义等价: 查找并调用 toolName 对应的工具处理器
        System.out.println("[tool-dispatch] " + toolName);
        return "dispatched: " + toolName;
    }
}
