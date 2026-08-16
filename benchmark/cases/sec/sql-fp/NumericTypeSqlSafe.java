/*
 * JSEF Benchmark — FP 混淆型安全样本（CWE-89, 难度 L3）
 *
 * 样本 1：泛型/包装数值类型 source 实为安全
 *   source 是 List<Long> / Optional<Long>（数字类型），即便拼入 Statement，
 *   也不可能构成 SQL 字符串注入——数值类型无注入语法。对照真 vuln 为 List<String>。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

import java.sql.Statement;
import java.util.List;
import java.util.Optional;

public class NumericTypeSqlSafe {

    /**
     * 安全入口：ids 为 List<Long> 数值集合，逐元素拼入 IN 子句。
     * 因元素类型为 Long，任何值都只是数字，无法注入 SQL 语法。
     * @param ids 不可信但被类型约束为数值的集合
     */
    static void safe(Statement stmt, List<Long> ids) throws Exception {
        StringBuilder in = new StringBuilder();
        for (Long id : ids) {
            in.append(id).append(",");
        }
        String sql = "SELECT * FROM users WHERE id IN (" + in + "0)";
        // [CHECKPOINT id=JSEF-FP-001 cwe=89 level=L3 source=List<Long> ids sink=Statement.execute(numeric concat) expect=SAFE]
        stmt.execute(sql);
    }

    /**
     * 安全入口：optId 为 Optional<Long>，存在才拼入数值参数，无注入可能。
     */
    static void safeOptional(Statement stmt, Optional<Long> optId) throws Exception {
        if (optId.isPresent()) {
            String sql = "SELECT * FROM users WHERE id = " + optId.get();
            // [CHECKPOINT id=JSEF-FP-002 cwe=89 level=L3 source=Optional<Long> optId sink=Statement.execute(numeric concat) expect=SAFE]
            stmt.execute(sql);
        }
    }
}
