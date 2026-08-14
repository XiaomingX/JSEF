/*
 * JSEF Benchmark — Phase 4 多后端注入变体（安全对照）
 * 样本 5-S：CallableStatement 固定过程名 + 参数绑定（CWE-89, 难度 L3）
 *
 * 与 StoredProcedureInjection 配对：过程名固定，参数经 setString 绑定，用户
 * 输入不进入 SQL 文本，故 expect=SAFE。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

import java.sql.Connection;
import java.sql.CallableStatement;

public class StoredProcedureInjectionSafe {

    /**
     * 安全入口：固定过程名 + setString 参数绑定。
     */
    static void safe(Connection conn, String id) throws Exception {
        CallableStatement cs = conn.prepareCall("{call sp_get_user(?)}");
        cs.setString(1, id);
        // [CHECKPOINT id=JSEF-SQL-005S cwe=89 level=L3 source=id sink=CallableStatement.execute(setString) expect=SAFE]
        cs.execute();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("StoredProcedureInjectionSafe demo (localhost only)");
    }
}
