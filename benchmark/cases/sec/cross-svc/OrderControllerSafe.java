package com.jsef.benchmark.sec.crosssvc;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * JSEF-Benchmark 样本族 B — 编排安全对照：跨 HTTP 边界参数化（CWE-89，L4）
 *
 * 难度：L4（跨 HTTP 边界，但下游回传前已参数化）
 *
 * 与 vuln/cross-svc/OrderController 同构：同样跨 HTTP 边界调用下游服务。
 * 区别在于下游不再把不可信 filter 拼进 SQL 片段回传，而是返回一个
 * "占位符 SQL 模板 + 参数列表"（语义等价 PreparedStatement 参数绑定），
 * 值不进入 SQL 文本，sink（queryForList 模板）不可被注入。
 *
 * 测试点：强 SAST/LLM 应识别"污点仅进入绑定参数、不进 SQL 文本"而不报
 * （TN）；弱工具易把"跨 HTTP 回传片段"误报（测 FP）。
 *
 * 修复要点：下游回传固定模板，查询侧用 PreparedStatement 参数绑定。
 *
 * 安全底线：仅 localhost 演示，不写真实攻击载荷。
 */
@RestController
public class OrderControllerSafe {

    private final ParamDataService dataService = new ParamDataService();

    /**
     * 安全入口：下游回传参数化模板 + 参数，queryForList 使用固定 SQL。
     */
    @GetMapping("/benchmark/crosssvc/orders/safe")
    public List<String> searchOrders(@RequestParam("filter") String filter) {
        // 下游回传参数化片段（污点仅进绑定参数，不进 SQL 文本）
        ParamDataService.SqlQuery q = dataService.fetchSqlFragment(filter);

        // [CHECKPOINT id=JSEF-OS-001S cwe=89 level=L4 source=@RequestParam filter sink=JdbcTemplate.queryForList(fixed template, param bound) expect=SAFE]
        return queryForList(q.template, q.param); // 固定模板，filter 仅作绑定参数
    }

    /**
     * 语义等价：JdbcTemplate.queryForList(template, param) —— 参数化查询。
     */
    static List<String> queryForList(String sql, Object param) {
        System.out.println("[queryForList-safe] " + sql + " params=" + param);
        return java.util.Collections.emptyList();
    }

    /** 安全下游服务桩（内嵌，演示参数化回传）。 */
    static class ParamDataService {
        /** 语义等价：下游把 filter 作为绑定参数，SQL 模板固定。 */
        SqlQuery fetchSqlFragment(String filter) {
            // 语义等价：PreparedStatement "SELECT * FROM orders WHERE status = ?" 绑定 filter
            return new SqlQuery("SELECT * FROM orders WHERE status = ?", filter);
        }

        static class SqlQuery {
            final String template;
            final Object param;
            SqlQuery(String template, Object param) {
                this.template = template;
                this.param = param;
            }
        }
    }
}
