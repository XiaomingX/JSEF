package com.jsef.benchmark.vuln.crosssvc;

/**
 * JSEF-Benchmark 样本族 B — 编排：下游服务桩（跨 HTTP 边界中间层）
 *
 * 角色：模拟"订单服务"调用的下游"数据服务"。本文件不设独立 checkpoint，
 * 仅作为 OrderController 跨 HTTP 边界链路的 trace 节点存在。
 *
 * 污点流：OrderController 把不可信 filter 作为 HTTP 出站参数传进来，
 * 本服务把它直接拼进 SQL 片段后作为响应回传。回传片段携带污点，
 * 回到 OrderController 的 queryForList sink。
 *
 * 为什么这里是合理非缺陷（对齐 plans/07 D5 约定）：辅助类不单独计
 * checkpoint，它只是主链路上的一个传递节点；真正的判定点（sink）在
 * OrderController。被测工具应沿跨 HTTP 边界的编排链，把本文件的
 * "拼 SQL 片段"识别为链路中间态。
 *
 * 安全底线：仅 localhost 演示，不写真实攻击载荷。
 */
public class DataService {

    /**
     * 下游数据服务接口（RestTemplate 语义桩）。
     *
     * @param filter 不可信 HTTP 参数（攻击者完全控制）
     * @return 拼接了不可信 filter 的 SQL 片段（携带污点）
     */
    public String fetchSqlFragment(String filter) {
        // 语义等价：restTemplate.getForObject("http://data-svc/sql?f=" + filter, String.class)
        // 出站请求把 filter 传给下游；此处是"下游服务被编排调用的转发方法"。
        String sql = "SELECT * FROM orders WHERE status = '" + filter + "'";
        // 中间节点：下游把拼好的 SQL 片段作为响应原样回传给调用方
        System.out.println("[data-svc] downstream returns fragment");
        return sql;
    }
}
