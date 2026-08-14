package com.jsef.benchmark.vuln;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * JSEF-Benchmark L4 — 跨文件调用链末端节点 Mapper（sink 所在）。
 *
 * 污点经 ChainSqlController -> ChainSqlService 一路透传至此，
 * 在 query 中直接把拼接 SQL 交给 Statement.executeQuery —— 危险 sink。
 *
 * CWE-89 SQL Injection。
 */
public class ChainSqlMapper {

    private final Connection conn;

    public ChainSqlMapper(Connection conn) {
        this.conn = conn;
    }

    /**
     * sink：不可信 sql 直接执行查询。
     */
    public String query(String sql) throws Exception {
        // 污点经 ChainSqlController -> ChainSqlService -> ChainSqlMapper 到达此处 executeQuery
        Statement stmt = conn.createStatement();
        // [CHECKPOINT id=JSEF-L4-SQL-002 cwe=89 level=L4 source=mapper sql sink=Statement.executeQuery expect=VULN trace=benchmark/cases/vuln/level4/ChainSqlController.java:34,benchmark/cases/vuln/level4/ChainSqlService.java:23]
        ResultSet rs = stmt.executeQuery(sql);
        return String.valueOf(rs.next());
    }
}
