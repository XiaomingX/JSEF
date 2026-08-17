package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L3 — 跨类静态字段安全对照
 *
 * 修复：读取静态字段后使用参数化查询（占位符 + 绑定参数）。
 * SAFE 侧按实现判定安全。
 */
public class StaticTaintSafe {

    public static class Sink {
        static void query(String t) {
            // [CHECKPOINT id=JSEF-NV505S cwe=89 level=L3 source=public static String T sink=jdbcTemplate (cross-class static taint) expect=SAFE]
            jdbcTemplateParam(t);
        }
    }

    // 抽象 sink：语义等价 jdbcTemplate.query("... where x = ?", param)
    static void jdbcTemplateParam(String param) {
        System.out.println("[sql-param] " + param);
    }

    public static void main(String[] args) {
        T = "1 OR 1=1";
        Sink.query(T);
    }

    public static String T;
}
