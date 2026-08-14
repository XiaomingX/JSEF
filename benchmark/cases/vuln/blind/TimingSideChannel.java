package com.jsef.benchmark.vuln;

/**
 * JSEF-Benchmark Phase5-C — 时序侧信道（CWE-208，难度 L4）
 *
 * 混淆点（为什么容易被误判）：
 * 代码里没有任何"危险的 IO 调用"或"拼接字符串交给解释器"，只是比较两个字符串。
 * 大多数 SAST/LLM 的注入/命令执行规则不会命中它，极易被当作"普通 equals"漏报（FN）。
 * 但 equals 在首个不匹配字符处即返回，导致比较时间与正确前缀长度成正比——
 * 攻击者可借响应时间差逐字符爆破密码，构成可利用的时序侧信道 VULN。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实爆破脚本。
 */
public class TimingSideChannel {

    static final String SECRET = "s3cr3t-password";

    /**
     * 危险入口：非恒定时间字符串比较（前缀早退）。
     */
    static boolean verify(String input) {
        // [CHECKPOINT id=JSEF-BL-003 cwe=208 level=L4 source=user input sink=String.equals (non-constant-time) expect=VULN]
        return SECRET.equals(input); // 早退：时间随正确前缀长度变化，可被爆破
    }
}
