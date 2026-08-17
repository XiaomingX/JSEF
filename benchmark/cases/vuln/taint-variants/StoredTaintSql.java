package com.jsef.benchmark.vuln;

import java.util.HashMap;
import java.util.Map;

/*
 * JSEF-Benchmark L4 — 存储型 / 二阶污点 SQLi
 *
 * 难度：L4（跨方法 / 隐式 source）。污点来源不是当次 HTTP 请求参数，而是
 * 先前“存储”在缓存 / 数据库中的值（如用户昵称、配置项）。常规 SAST 习惯从
 * @RequestParam 找 source，会在此漏报——因为 source 在 loadFromStore() 内部，
 * 需跨方法识别“从存储读出即污点”。
 *
 * CWE-89 (SQL Injection)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 StoredTaintSqlSafe.java）：从存储读出的值同样视为不可信，
 * 必须经参数化查询或校验后才能进入 SQL。
 */
public class StoredTaintSql {

    // 模拟“存储层”：先前由不可信输入写入的值（如昵称、配置）
    static final Map<String, String> STORE = new HashMap<>();

    /**
     * 隐式 source：从存储读出的值可能来自历史不可信输入。
     */
    static String loadFromStore(String key) {
        return STORE.getOrDefault(key, "default");
    }

    /**
     * 业务方法：用存储中的值做“二次查询”（二阶注入场景）。
     *
     * @param key 存储键
     */
    public void queryByStoredValue(String key) {
        String stored = loadFromStore(key); // 污点：来自存储，非当次请求
        // [CHECKPOINT id=JSEF-TV-001 cwe=89 level=L4 source=loadFromStore(key) (stored/2nd-order taint) sink=jdbcTemplate.queryForList expect=VULN trace=benchmark/cases/vuln/taint-variants/StoredTaintSql.java:37,benchmark/cases/vuln/taint-variants/StoredTaintSql.java:41]
        jdbcTemplateQuery(stored); // 存储值直接拼入 SQL
    }

    // 抽象 sink：语义等价 jdbcTemplate.queryForList(sql)
    static void jdbcTemplateQuery(String sql) {
        System.out.println("[sql-exec] " + sql);
    }

    public static void main(String[] args) {
        STORE.put("nick", "' OR '1'='1");
        new StoredTaintSql().queryByStoredValue("nick");
    }
}
