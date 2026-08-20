package com.jsef.benchmark.vuln;

/**
 * JSEF-Benchmark L4 — 无害干扰节点（Decoy，非路径节点）。
 *
 * 污点虽然经过本类的 transform()，但仅做 base64 解码后即返回，
 * 结果并未进入任何 sink。本节点是调用链中的"干扰节点"，
 * 用于测 trace_precision：模型不应把本节点报为污点到达 sink 的真路径。
 *
 * 难点/区分点：跨文件链中混入无害转换节点，纯可达性分析会把所有
 * source→sink 途经节点都当路径，而精确 trace 须识别"数据真正到达 sink"的真节点。
 *
 * CWE-78 OS Command Injection（本类为无 sink 的干扰节点，本身不构成漏洞）。
 */
public class TraceDistractorDecoy {

    private static final java.util.Base64.Encoder B64 = java.util.Base64.getEncoder();

    /**
     * 无害转换：对输入做 base64 编码，结果仅用于日志输出，不进入任何危险 sink。
     */
    public String transform(String input) {
        String encoded = B64.encodeToString(input.getBytes()); // 无害变换，污点未流入 sink
        return encoded;
    }
}
