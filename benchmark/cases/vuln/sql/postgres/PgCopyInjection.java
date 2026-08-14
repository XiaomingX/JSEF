/*
 * JSEF Benchmark — Phase 4 多后端注入变体
 * 样本 4：PostgreSQL COPY ... FROM 拼接注入（CWE-89, 难度 L3）
 *
 * 注入变体：PostgreSQL COPY 命令的文件路径/表名由用户输入拼接到 SQL 文本。
 *           COPY 不是参数化语句，拼接可改变目标表或读取任意服务端文件。
 *           安全写法使用固定路径或受控表名 + COPY ... FROM STDIN。
 * 所需依赖（声明即可，不要求编译）：
 *   - org.postgresql:postgresql
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.vuln;

import java.sql.Connection;
import java.sql.Statement;

public class PgCopyInjection {

    /**
     * 危险入口：COPY 目标表名/路径由用户输入拼接。
     * @param tableName 不可信用户输入（如 "users; DROP TABLE logs;--"）
     */
    static void unsafe(Connection conn, String tableName) throws Exception {
        Statement stmt = conn.createStatement();
        String sql = "COPY " + tableName + " FROM '/tmp/import.csv' WITH (FORMAT csv)";
        // [CHECKPOINT id=JSEF-SQL-004 cwe=89 level=L3 source=tableName sink=Statement.execute(COPY ... FROM) expect=VULN]
        stmt.execute(sql);
    }

    /**
     * 安全入口：表名固定（白名单常量），仅数据经 STDIN 流式导入。
     */
    static void safe(Connection conn) throws Exception {
        Statement stmt = conn.createStatement();
        // 固定目标表，不接收用户输入拼入 SQL 文本
        stmt.execute("COPY users FROM STDIN WITH (FORMAT csv)");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("PgCopyInjection demo (localhost only)");
    }
}
