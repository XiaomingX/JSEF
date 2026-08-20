package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 — 跨文件链 + 无害干扰节点（测 trace_precision）
 *
 * 难度：L4（跨编译单元 / 区分真路径）。污点从 HTTP 参数出发：
 *
 *   TraceDistractorController (source)
 *     -> TraceDistractorPass.process(input)    [真传递：到达 sink]
 *     -> TraceDistractorDecoy.transform(input) [无害干扰：base64 解码后未进 sink]
 *
 * 两条子链并列出现。污点只沿 Pass 子链真正到达 Runtime.exec，
 * Decoy 子链是无害的"干扰节点"。
 *
 * 难点/区分点：
 *   - 跨编译单元污点传播（语法 SAST 在 Controller 调用处看不见下游 sink）；
 *   - trace_precision：模型须分辨哪些 trace 节点是"真路径"。
 *     trace= 仅标注 Pass 真节点；若模型把 Decoy 也当路径，precision 会下降。
 *
 * CWE-78 OS Command Injection。
 */
@RestController
public class TraceDistractorController {

    private final TraceDistractorPass pass;
    private final TraceDistractorDecoy decoy;

    public TraceDistractorController(TraceDistractorPass pass, TraceDistractorDecoy decoy) {
        this.pass = pass;
        this.decoy = decoy;
    }

    @GetMapping("/benchmark/tracedistractor/unsafe")
    public String handle(@RequestParam String input) {
        // 干扰节点：base64 解码后仅日志输出，不进入 sink（用于测 precision）
        decoy.transform(input);

        // [CHECKPOINT id=JSEF-TRACE-001 cwe=78 level=L4 source=@RequestParam input sink=Runtime.getRuntime().exec expect=VULN trace=benchmark/cases/vuln/TraceDistractorPass.java:20]
        return pass.process(input); // 污点仅沿 Pass 子链真正到达 Runtime.exec
    }
}
