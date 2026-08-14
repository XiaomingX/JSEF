/*
 * JSEF Benchmark 样本 — AI/Agent 能力边界绕过：指令绕过工具白名单（VulnGym 子类 BL-AGENT-CAPABILITY，CWE-285，L4）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"策略语义"——agent 设定了工具白名单，但白名单校验逻辑可被 prompt 指令绕过
 *（如通过特殊前缀让校验短路）。数据流干净，但白名单策略的前提被破坏。
 * 静态分析需在白名单判定处识别"指令可绕过 allowlist 校验"这一状态机缺陷。
 */
package com.jsef.benchmark.vuln;

public class AgentIntentBypass {

    // 演示用：白名单与请求
    static final java.util.Set<String> ALLOWED = java.util.Set.of("search", "summarize");

    // 危险：白名单校验可被请求里的特殊指令绕过
    static boolean isAllowed(String intent) {
        // source：不可信 user intent（HTTP 参数，含可绕过指令）
        // [CHECKPOINT id=JSEF-V1-AGT-002 cwe=285 level=L4 source=user intent (prompt) sink=allowlist bypass (no guard) expect=VULN]
        if (intent.startsWith("@@override")) {
            return true;   // 攻击者用 @@override 绕过白名单
        }
        return ALLOWED.contains(intent);
    }
}
