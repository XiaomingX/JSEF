// [VULN]
package com.jsef.benchmark.vuln.msprecon;

/**
 * JSEF-Benchmark — 多步规划 P3：跨文件侦察链中间节点（Repo，L4）
 *
 * 把不可信 sortField 拼入 Spring Data 方法名，由框架生成 SQL —— 隐式 SQL 注入。
 * 语义等价：findBy<Field> 的方法名被框架转为 "order by <Field>"，Field 来自不可信输入。
 */
public class ReconChainSql_Repo {

    private final ReconChainSql_Sink sink;

    public ReconChainSql_Repo(ReconChainSql_Sink sink) {
        this.sink = sink;
    }

    /**
     * 污点透传：不可信 sortField 成为派生查询方法名的一部分。
     */
    public Object findByDynamic(String sortField) {
        String methodName = "findBy" + sortField; // 语义等价：排序字段拼接进方法名
        return sink.runQuery(methodName);
    }
}
