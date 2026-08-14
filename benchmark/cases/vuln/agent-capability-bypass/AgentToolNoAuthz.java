/*
 * JSEF Benchmark 样本 — AI/Agent 能力边界绕过：工具调用未校验调用方权限（VulnGym 子类 BL-AGENT-CAPABILITY，CWE-285，L3）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"业务授权语义"——agent 框架把任意用户请求直接路由到敏感工具（如 bank_transfer），
 * 未校验"当前调用方是否拥有该工具的权限"。数据流干净，但缺失调用方授权检查。
 * 静态分析需在 tool.execute() 处识别"调用方权限未被校验"这一前提。
 */
package com.jsef.benchmark.vuln;

public class AgentToolNoAuthz {

    // 演示用：工具接口与调用上下文
    static final class Tool { final String name; Tool(String name){ this.name = name; } }
    static final class Caller { final String id; final java.util.Set<String> perms;
        Caller(String id, java.util.Set<String> perms){ this.id=id; this.perms=perms; } }

    // 危险：agent 直接执行用户点名的工具，未校验 caller 权限
    static Object invokeAgentTool(Tool tool, Caller caller) {
        // source：不可信 caller 请求（HTTP 参数，攻击者可控工具名）
        // [CHECKPOINT id=JSEF-V1-AGT-001 cwe=285 level=L3 source=caller-requested tool name sink=tool.execute() (no caller permission check) expect=VULN]
        return tool.executeFor(caller);   // 越权：任意 caller 可调用敏感工具
    }
}
