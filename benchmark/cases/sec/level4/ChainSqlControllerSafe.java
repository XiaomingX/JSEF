package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L4 — ChainSqlController 安全对照（SAFE 混淆样本）
 *
 * 安全做法：在 Mapper 末端改用参数化查询（PreparedStatement），
 * 不可信输入仅作为绑定参数，不进入 SQL 字符串。用于计算 TN / FP。
 *
 * CWE-89 SQL Injection。
 */
@RestController
public class ChainSqlControllerSafe {

    private final ChainSqlServiceSafe service;

    public ChainSqlControllerSafe(ChainSqlServiceSafe service) {
        this.service = service;
    }

    @GetMapping("/benchmark/chainsql/safe")
    public String handle(@RequestParam String input) {
        // [CHECKPOINT id=JSEF-L4-SQL-001S cwe=89 level=L4 source=@RequestParam input sink=Statement.executeQuery expect=SAFE]
        return service.process(input); // 链路末端以 PreparedStatement 参数化执行
    }
}
