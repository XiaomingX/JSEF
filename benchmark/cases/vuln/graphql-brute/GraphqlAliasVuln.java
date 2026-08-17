package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L3 — GraphQL 别名批量查询暴力枚举 (无成本/速率限制)
 *
 * 难度：L3（跨方法 / 间接）。客户端用别名批量发起同结构查询
 * (query {a:user(id:1) b:user(id:1) ...}) 绕过单点限制，无别名数 / 复杂度 /
 * 速率限制，导致暴力枚举或 DoS。污点经别名结构汇聚到 execute sink，纯语法 SAST
 * 难识别"别名数量"这一业务逻辑缺口。
 *
 * CWE-307 (Improper Restriction of Excessive Authentication Attempts)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 GraphqlAliasSafe.java）：限制别名数 + 速率限制。
 */
public class GraphqlAlias {

    /**
     * @param aliasedQueries 用户构造的别名批量查询字符串
     */
    public void run(String aliasedQueries) {
        // [CHECKPOINT id=JSEF-NV511 cwe=307 level=L3 source=aliasedQueries sink=graphql execute (no rate/cost limit) expect=VULN]
        execute(aliasedQueries);     // 无别名数 / 成本限制直接执行
    }

    // 抽象 sink：语义等价 GraphQL.execute(query)
    static void execute(String query) {
        System.out.println("[graphql] " + query);
    }

    public static void main(String[] args) {
        new GraphqlAlias().run("{a:user(id:1) b:user(id:1) c:user(id:1) ...}");
    }
}
