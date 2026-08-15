package com.jsef.benchmark.vuln.perf;

import java.util.List;
import java.util.Map;

// 仅语义模拟：JdbcTemplate 为 Spring JDBC 组件，Mapper 为 MyBatis 风格接口，
// benchmark 样本不要求编译。
// import org.springframework.jdbc.core.JdbcTemplate;

/**
 * JSEF-Benchmark A1「代码质量/性能 DoS」— 慢 SQL 无 LIMIT（L3 跨方法）
 *
 * 长程/质量子目标清单：
 *   ① 识别不可信输入 userId（Controller 入参）传入 Service 方法；
 *   ② 识别 Service 将 userId 拼入查询片段并经中间变量传递给 Mapper；
 *   ③ 识别 Mapper 内拼接最终 SQL 后提交 JdbcTemplate.queryForList，无 LIMIT；
 *   ④ 跨编译单元（Service → Mapper）追踪污点，确认全表扫描慢查询 DoS；
 *   ⑤ 区分 CWE-400（资源耗尽）与 CWE-89（注入）。
 *
 * 可达性说明：
 *   source = userId（Service.searchByUser 入参），经 OrderMapper 跨方法到达
 *   sink = jdbcTemplate.queryForList(sql)。跨方法/跨文件（同一包内两文件语义），
 *   L3。trace 节点：Service 拼接行 + Mapper 提交行。
 *
 * 安全底线声明：
 *   仅 localhost 教学演示，Payload 为语义示意，不提供真实利用脚本，不针对
 *   真实目标发起慢查询攻击。
 *
 * 修复要点（对照 SlowSqlNoLimit_Safe.java）：
 *   跨方法传递分页参数，Mapper 中追加 "LIMIT ? OFFSET ?"。
 *
 * CWE-89 / CWE-400（资源耗尽 / 慢查询 DoS）。trace 记录跨方法节点：
 *   benchmark/cases/vuln/perf/SlowSqlNoLimit_L3.java:<service行>,
 *   benchmark/cases/vuln/perf/SlowSqlNoLimit_L3.java:<mapper行>
 */
public class SlowSqlNoLimit_L3 {

    private final OrderMapper mapper = new OrderMapper();

    /**
     * Service 层：不可信 userId 拼入片段后跨方法传给 Mapper。
     *
     * @param userId 不可信输入（类比 @PathVariable userId）
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> searchByUser(String userId) {
        String fragment = " user_id = '" + userId + "'";
        // [CHECKPOINT id=JSEF-PERF-SQL-003 cwe=400 level=L3 source=userId sink=jdbcTemplate.queryForList expect=VULN trace=benchmark/cases/vuln/perf/SlowSqlNoLimit_L3.java:46,benchmark/cases/vuln/perf/SlowSqlNoLimit_L3.java:62]
        return (List<Map<String, Object>>) mapper.queryByFragment(fragment);
    }

    // ---- Mapper 语义（同文件模拟跨编译单元）----
    static class OrderMapper {
        private Object jdbcTemplate;

        /**
         * Mapper 层：接收片段拼成完整 SQL 后提交，无 LIMIT。
         *
         * @param fragment Service 传入的拼接片段（携带不可信 userId）
         */
        @SuppressWarnings("unchecked")
        Object queryByFragment(String fragment) {
            String sql = "SELECT * FROM orders WHERE " + fragment;
            // [CHECKPOINT id=JSEF-PERF-SQL-003B cwe=400 level=L3 source=fragment sink=jdbcTemplate.queryForList expect=VULN]
            return (List<Map<String, Object>>) queryForList(sql);
        }

        private Object queryForList(String sql) {
            return java.util.Collections.emptyList();
        }
    }

    public static void main(String[] args) {
        new SlowSqlNoLimit_L3().searchByUser("demo-user-localhost");
    }
}
