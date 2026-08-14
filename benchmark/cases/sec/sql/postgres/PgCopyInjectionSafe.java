/*
 * JSEF Benchmark — Phase 4 多后端注入变体（安全对照）
 * 样本 4-S：PostgreSQL COPY 固定表名（CWE-89, 难度 L3）
 *
 * 与 PgCopyInjection 配对：COPY 目标表固定，不接收用户输入拼入 SQL 文本，
 * 数据经 STDIN 流式导入，故 expect=SAFE。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

import java.sql.Connection;
import java.sql.Statement;

public class PgCopyInjectionSafe {

    /**
     * 安全入口：固定目标表 + COPY ... FROM STDIN。
     */
    static void safe(Connection conn) throws Exception {
        Statement stmt = conn.createStatement();
        // [CHECKPOINT id=JSEF-SQL-004S cwe=89 level=L3 source=(none) sink=Statement.execute(COPY users FROM STDIN) expect=SAFE]
        stmt.execute("COPY users FROM STDIN WITH (FORMAT csv)");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("PgCopyInjectionSafe demo (localhost only)");
    }
}
