package com.jsef.benchmark.vuln;

/**
 * JSEF-Benchmark L4 — 跨文件调用链中间节点 A。
 *
 * 仅对不可信输入做"加工"（此处为语义无关的包装，不净化），
 * 污点透传到 ChainServiceB.execute。
 *
 * CWE-78 OS Command Injection。
 */
public class ChainServiceA {

    private final ChainServiceB serviceB;

    public ChainServiceA(ChainServiceB serviceB) {
        this.serviceB = serviceB;
    }

    /**
     * 透传加工：污点语义不变，仅拼接演示用后缀。
     */
    public String process(String input) {
        String data = input + " ; echo localhost";
        return serviceB.execute(data); // 污点 data 继续跨编译单元流向 ChainServiceB
    }
}
