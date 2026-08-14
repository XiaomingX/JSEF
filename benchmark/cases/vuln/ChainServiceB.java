package com.jsef.benchmark.vuln;

import java.io.IOException;

/**
 * JSEF-Benchmark L4 — 跨文件调用链末端节点 B（sink 所在）。
 *
 * 污点经 ChainController -> ChainServiceA 一路透传至此，
 * 在 execute 中直接传入 Runtime.getRuntime().exec —— 危险 sink。
 *
 * CWE-78 OS Command Injection。
 */
public class ChainServiceB {

    /**
     * sink：不可信 data 直接进入命令执行。
     */
    public String execute(String data) throws IOException {
        // 污点经 ChainController -> ChainServiceA -> ChainServiceB 到达此处 Runtime.exec
        Process p = Runtime.getRuntime().exec(data);
        return "executed pid=" + p.pid();
    }
}
