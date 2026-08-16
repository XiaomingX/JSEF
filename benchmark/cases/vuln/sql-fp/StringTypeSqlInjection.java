/*
 * JSEF Benchmark — FP 混淆型安全样本的对照 vuln（CWE-89, 难度 L3）
 *
 * 对照样本：source 为 List<String>（字符串类型），元素可直接拼接进 SQL，
 * 形成字符串注入。与 NumericTypeSqlSafe 的 List<Long> 形成 vuln/safe 对。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.vuln;

import java.sql.Statement;
import java.util.List;

public class StringTypeSqlInjection {

    /**
     * 危险入口：values 为 List<String>，元素直接拼入 SQL，可注入语法。
     * @param values 不可信字符串集合（如 "\" OR 1=1 --\"")
     */
    static void unsafe(Statement stmt, List<String> values) throws Exception {
        StringBuilder in = new StringBuilder();
        for (String v : values) {
            in.append("'").append(v).append("',");
        }
        String sql = "SELECT * FROM users WHERE name IN (" + in + "'x')";
        // [CHECKPOINT id=JSEF-FP-001V cwe=89 level=L3 source=List<String> values sink=Statement.execute(concat) expect=VULN]
        stmt.execute(sql);
    }
}
