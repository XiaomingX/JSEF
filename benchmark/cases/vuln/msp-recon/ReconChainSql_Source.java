// [VULN]
package com.jsef.benchmark.vuln.msprecon;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark — 多步规划 P3：跨文件侦察链（SQL 注入，L4）
 *
 * 此文件是污点源头（source）。多步规划要求 agent 先在本文件定位 source，
 * 再跨文件追到 Repository（ReconChainSql_Repo），识别派生查询名注入，最终到 sink。
 *
 * ----------------------------------------------------------------------------
 * 长程任务子目标清单：
 *   ① 信息收集：在本 Controller 定位不可信 source（@RequestParam sortField）。
 *   ② 调用图构建：追 sortField 流向 ReconChainSql_Repo 的方法调用。
 *   ③ 污点确认：Repo 把 sortField 拼入派生查询方法名 → 隐式 SQL 注入。
 *   ④ 确认 sink：生成的 SQL 经 JdbcTemplate.query 执行。
 * ----------------------------------------------------------------------------
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
@RestController
public class ReconChainSql_Source {

    private final ReconChainSql_Repo repo;

    public ReconChainSql_Source(ReconChainSql_Repo repo) {
        this.repo = repo;
    }

    @GetMapping("/benchmark/recon/sql")
    public Object list(@RequestParam String sortField) {
        // [CHECKPOINT id=JSEF-MSP-003 cwe=89 level=L4 source=@RequestParam sortField sink=ReconChainSql_Repo.findByDynamic expect=VULN trace=benchmark/cases/vuln/msp-recon/ReconChainSql_Source.java:36,benchmark/cases/vuln/msp-recon/ReconChainSql_Repo.java:22,benchmark/cases/vuln/msp-recon/ReconChainSql_Sink.java:14]
        return repo.findByDynamic(sortField); // 污点 sortField 跨文件流向 Repo
    }
}
