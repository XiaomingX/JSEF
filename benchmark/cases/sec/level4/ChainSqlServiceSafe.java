package com.jsef.benchmark.sec;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * JSEF-Benchmark L4 — 跨文件调用链安全版中间/末端节点。
 *
 * Service 仅透传参数；Mapper 使用 PreparedStatement 参数化，污点不入 SQL。
 *
 * CWE-89 SQL Injection。
 */
public class ChainSqlServiceSafe {

    private final ChainSqlMapperSafe mapper;

    public ChainSqlServiceSafe(ChainSqlMapperSafe mapper) {
        this.mapper = mapper;
    }

    public String process(String input) {
        return mapper.query(input);
    }
}

class ChainSqlMapperSafe {

    private final Connection conn;

    public ChainSqlMapperSafe(Connection conn) {
        this.conn = conn;
    }

    public String query(String param) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM items WHERE cat = ?");
        ps.setString(1, param);
        // [CHECKPOINT id=JSEF-L4-SQL-002S cwe=89 level=L4 source=mapper param sink=PreparedStatement.executeQuery expect=SAFE]
        ResultSet rs = ps.executeQuery();
        return String.valueOf(rs.next());
    }
}
