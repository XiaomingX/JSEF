package com.jsef.benchmark.vuln;

// 运行态需 JSEF 依赖：本文件为自包含 benchmark 样本，使用 Spring 注解仅为演示
// 跨文件调用链语义（CAP-07 跨编译单元）。实际运行需 Spring Web 依赖，此处不强求编译。

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L4 — 跨文件调用链（命令注入）
 *
 * 难度：L4（跨编译单元）。污点从 HTTP 参数出发，跨越 3 个独立编译单元：
 *   ChainController (source)
 *     -> ChainServiceA.process(input)
 *        -> ChainServiceB.execute(data)  [sink: Runtime.exec]
 *
 * 纯语法 SAST 若不跨文件做可达性分析，会在 Controller 调用处"看不见"下游 sink。
 * 需要跨文件 / 跨过程的数据流分析才能从 source 一路追踪到 Runtime.exec。
 *
 * CWE-78 OS Command Injection。
 */
@RestController
public class ChainController {

    private final ChainServiceA serviceA;

    public ChainController(ChainServiceA serviceA) {
        this.serviceA = serviceA;
    }

    @GetMapping("/benchmark/chain/unsafe")
    public String handle(@RequestParam String input) {
        // [CHECKPOINT id=JSEF-CHAIN-001 cwe=78 level=L4 source=@RequestParam input sink=Runtime.exec expect=VULN]
        return serviceA.process(input); // 污点 input 跨编译单元流向 ChainServiceA -> ChainServiceB(Runtime.exec)
    }
}
