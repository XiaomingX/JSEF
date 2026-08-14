package com.jsef.benchmark.vuln;

// 运行态需 JSEF 依赖：本文件为自包含 benchmark 样本，使用 Spring 注解仅为演示
// 跨文件调用链语义（CAP-07 跨编译单元）。实际运行需 Spring Web 依赖，此处不强求编译。

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L4 — 跨文件调用链（SQL 注入）
 *
 * 难度：L4（跨编译单元）。污点从 HTTP 参数出发，跨越 3 个独立编译单元：
 *   ChainSqlController (source)
 *     -> ChainSqlService.process(input)
 *        -> ChainSqlMapper.query(sql)  [sink: Statement.executeQuery]
 *
 * 纯语法 SAST 若不跨文件做可达性分析，会在 Controller 调用处"看不见"下游 SQL sink。
 * 需要跨文件 / 跨过程的数据流分析才能从 source 一路追踪到拼接 SQL 的 executeQuery。
 *
 * CWE-89 SQL Injection。
 */
@RestController
public class ChainSqlController {

    private final ChainSqlService service;

    public ChainSqlController(ChainSqlService service) {
        this.service = service;
    }

    @GetMapping("/benchmark/chainsql/unsafe")
    public String handle(@RequestParam String input) {
        // [CHECKPOINT id=JSEF-L4-SQL-001 cwe=89 level=L4 source=@RequestParam input sink=Statement.executeQuery expect=VULN trace=benchmark/cases/vuln/level4/ChainSqlService.java:23,benchmark/cases/vuln/level4/ChainSqlMapper.java:29]
        return service.process(input); // 污点 input 跨编译单元流向 ChainSqlService -> ChainSqlMapper
    }
}
