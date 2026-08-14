/*
 * JSEF Benchmark 真假混淆样本 — SQL 白名单（B5，CWE-89）
 * VULN 版：用户输入直接拼 SQL。
 * 文件头说明：独立 benchmark 源文件，使用模拟 jdbcTemplate 表达 sink，不强求编译。
 */
public class ConfusionSqlWhitelist {

    static java.util.List<?> query(String sql) {
        // 模拟：org.springframework.jdbc.core.JdbcTemplate.queryForList
        return java.util.List.of(); // SINK（语义）
    }

    /**
     * 危险入口：用户输入直接拼入 SQL 字符串。
     */
    static java.util.List<?> unsafe(String userInput) { // source：不可信用户输入
        String sql = "SELECT * FROM users WHERE name = '" + userInput + "'";
        // [CHECKPOINT id=JSEF-CONF-SQL-001 cwe=89 level=L1 source=user input sink=jdbcTemplate.queryForList expect=VULN]
        return query(sql); // 污点直连 sink：SQL 注入
    }
}
