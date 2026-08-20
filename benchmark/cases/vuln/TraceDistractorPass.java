package com.jsef.benchmark.vuln;

/**
 * JSEF-Benchmark L4 — 跨文件真传递链中间节点（真路径）。
 *
 * 污点从 TraceDistractorController 出发，经过本类 process() 真实透传，
 * 最终进入 Runtime.exec。本类是 trace 证据链上的"真节点"。
 *
 * 难点/区分点：评测 trace_precision 时，模型必须把本节点判为真路径——
 * 它与 TraceDistractorDecoy 并列出现在调用链中，但只有本节点的数据真正到达 sink。
 *
 * CWE-78 OS Command Injection。
 */
public class TraceDistractorPass {

    /**
     * 真传递：不可信输入仅做无害拼接，污点语义不变，继续流向 sink。
     */
    public String process(String input) {
        String cmd = input; // 污点直接透传（本行是 trace 真节点）
        return run(cmd);    // 语义等价：Runtime.exec(cmd)
    }

    // 语义桩：VULN 侧信方法名/注释声明（见 AGENTS.md 抽象桩约定）
    private String run(String cmd) {
        System.out.println("[cmd-exec] " + cmd); // 语义等价: Runtime.exec(cmd)
        return "ran: " + cmd;
    }
}
