/*
 * JSEF Benchmark 样本 — AI/Agent 能力边界绕过：工具调用权限校验（safe 对照，CWE-285，L3）
 * 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

public class AgentToolNoAuthzSafe {

    static final class Tool { final String name; Tool(String name){ this.name = name; } }
    static final class Caller { final String id; final java.util.Set<String> perms;
        Caller(String id, java.util.Set<String> perms){ this.id=id; this.perms=perms; } }

    // 安全：执行前强制校验调用方是否拥有该工具的权限
    static Object invokeAgentTool(Tool tool, Caller caller) {
        // [CHECKPOINT id=JSEF-V1-AGT-001S cwe=285 level=L3 source=caller-requested tool name sink=tool.execute() (caller permission checked) expect=SAFE]
        if (!caller.perms.contains(tool.name)) {
            throw new SecurityException("caller lacks permission for tool: " + tool.name);
        }
        return tool.executeFor(caller);
    }
}
