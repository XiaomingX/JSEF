/*
 * JSEF Benchmark 样本 — AI/Agent 能力边界绕过：agent 自我提升权限等级（VulnGym 子类 BL-AGENT-CAPABILITY，CWE-285，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"权限状态语义"——agent 的权限等级从请求体读取并被自身写回提升，
 * 服务端未对"agent 可修改自身 level"做不可变约束。数据流干净，但权限来源不可信。
 * 静态分析需在 setLevel() 处识别"权限等级由不可信输入设定且无服务端约束"。
 */
package com.jsef.benchmark.vuln;

public class AgentPrivilegeEscalate {

    // 演示用：agent 上下文
    static final class AgentCtx { String level; }
    static final class Req { String requestedLevel; }

    // 危险：agent 把请求里的 level 当作自身权限等级，可自我提权
    static void applyLevel(AgentCtx ctx, Req req) {
        // source：不可信 req.requestedLevel（HTTP 参数，agent 可控）
        // [CHECKPOINT id=JSEF-V1-AGT-003 cwe=285 level=L4 source=req.requestedLevel sink=ctx.level = requestedLevel (self-escalation) expect=VULN]
        ctx.level = req.requestedLevel;   // 越权：agent 自我提升到 admin
    }
}
