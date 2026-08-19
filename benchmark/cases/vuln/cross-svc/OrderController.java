package com.jsef.benchmark.vuln.crosssvc;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * JSEF-Benchmark 样本族 B — 编排：跨 HTTP 边界污点传播（CWE-89，L4）
 *
 * 难度：L4（跨进程边界 / 微服务间 HTTP 调用的间接污点）
 *
 * 链路（跨 HTTP 边界，非进程内跨模块）：
 *   1) @RequestParam filter                 (source：不可信 HTTP 参数)
 *   2) dataService.fetchSqlFragment(filter) -> 经 RestTemplate 调下游 DataService
 *      （语义桩：HTTP 调用语义，见 DataService.java:31）
 *   3) 下游把"拼接了不可信 filter 的 SQL 片段"作为响应回传
 *      （DataService.java:33 fetchSqlFragment 方法体）
 *   4) OrderController 把回传片段直接拼入 queryForList(sql)     (sink)
 *
 * 为什么是"编排"：现有 longrange/bizlogic5 的链都是进程内同一 JVM 的
 * 跨模块。本样本的污点要先离开进程（RestTemplate 出站请求）、经下游服务
 * 处理后原样回传，再回到本进程进入 sink。单编译单元 SAST 只能看到
 * "fetchSqlFragment 的返回值拼进 queryForList"，但"该返回值本质是攻击者
 * 可控 filter 的直达"需要跨 HTTP 边界的服务编排语义才能还原——这正是
 * 跨服务调用链（service mesh / microservice choreography）的编排盲区。
 *
 * 修复要点：下游不得把不可信输入直接拼进 SQL 片段返回；查询侧使用
 * PreparedStatement 参数化绑定（值不进 SQL 文本）。对照 OrderControllerSafe。
 *
 * 安全底线：仅 localhost 演示，不写真实攻击载荷。
 */
@RestController
public class OrderController {

    private final DataService dataService = new DataService();

    /**
     * 危险入口：把不可信 filter 交给下游服务，回传片段直接拼 SQL。
     */
    @GetMapping("/benchmark/crosssvc/orders")
    public List<String> searchOrders(@RequestParam("filter") String filter) {
        // 入口：不可信 filter 进入链路
        // 中间节点：出站调用下游服务，回传带污点的 SQL 片段（见 DataService.java:33）
        String sqlFragment = dataService.fetchSqlFragment(filter);

        // [CHECKPOINT id=JSEF-OS-001 cwe=89 level=L4 source=@RequestParam filter sink=JdbcTemplate.queryForList(concat downstream fragment) expect=VULN trace=benchmark/cases/vuln/cross-svc/DataService.java:33,benchmark/cases/vuln/cross-svc/DataService.java:31]
        return queryForList(sqlFragment); // 污点跨 HTTP 边界回传后拼入查询
    }

    /**
     * 语义等价：JdbcTemplate.queryForList(sql, ...) —— SQL 由下游回传片段拼接。
     */
    static List<String> queryForList(String sql) {
        // 语义等价：jdbcTemplate.queryForList(sql, String.class)
        System.out.println("[queryForList] " + sql);
        return java.util.Collections.emptyList();
    }
}
