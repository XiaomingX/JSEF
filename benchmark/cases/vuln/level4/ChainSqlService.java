package com.jsef.benchmark.vuln;

/**
 * JSEF-Benchmark L4 — 跨文件调用链中间节点 Service。
 *
 * 仅对不可信输入做"加工"（此处为语义无关的包装，不净化），
 * 污点拼接后透传到 ChainSqlMapper.query。
 *
 * CWE-89 SQL Injection。
 */
public class ChainSqlService {

    private final ChainSqlMapper mapper;

    public ChainSqlService(ChainSqlMapper mapper) {
        this.mapper = mapper;
    }

    /**
     * 透传加工：污点语义不变，仅拼接演示用后缀形成 SQL 片段。
     */
    public String process(String input) {
        String sql = "SELECT * FROM items WHERE cat = '" + input + "'";
        return mapper.query(sql); // 污点 sql 继续跨编译单元流向 ChainSqlMapper
    }
}
