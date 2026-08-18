// [VULN]
package com.jsef.benchmark.vuln.msprecon;

/**
 * JSEF-Benchmark — 多步规划 P3：跨文件侦察链末端节点（sink，L4）
 *
 * 把 Repo 拼出的方法名（含不可信 sortField）当作 SQL 排序子句执行 —— 危险 sink。
 */
public class ReconChainSql_Sink {

    /**
     * sink：不可信查询片段直接进入 SQL 执行。
     */
    public Object runQuery(String sqlFragment) {
        // 语义等价：JdbcTemplate.query("select * from t order by " + sqlFragment)
        System.out.println("[abstract sql] select * from t order by " + sqlFragment);
        return "rows";
    }
}
