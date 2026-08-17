package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L3 — 跨类静态字段污点传播
 *
 * 难度：L3（跨类 / 跨方法）。不可信输入写入类 A 的 public static 字段 T，
 * 类 B 的静态方法读取 T 拼入 SQL，污点经静态字段跨越编译单元隐式传递，
 * 纯语法 SAST 需跨类追踪静态字段写入→读取，易断链漏报。
 *
 * CWE-89 (SQL Injection)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 StaticTaintSafe.java）：读取后使用参数化查询。
 */
public class StaticTaint {

    public static class Sink {
        // [CHECKPOINT id=JSEF-NV505 cwe=89 level=L3 source=public static String T sink=jdbcTemplate (cross-class static taint) expect=VULN trace=benchmark/cases/vuln/static-taint/StaticTaintVuln.java:31,benchmark/cases/vuln/static-taint/StaticTaintVuln.java:32]
        static void query(String t) {
            jdbcTemplate(t);              // 读取静态字段 T 拼 SQL（trace 节点②）
        }
    }

    // 抽象 sink：语义等价 jdbcTemplate.query(sql)
    static void jdbcTemplate(String sql) {
        System.out.println("[sql] " + sql);
    }

    public static void main(String[] args) {
        // 类 A（此处即本类）写入静态污点（trace 节点①）
        T = "1 OR 1=1";
        Sink.query(T);
    }

    // 不可信静态字段（类 A 持有）
    public static String T;
}
