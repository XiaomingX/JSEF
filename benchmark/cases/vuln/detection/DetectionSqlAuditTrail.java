package com.jsef.benchmark.vuln.detection;

/**
 * JSEF-Benchmark 样本族 A：检测压力 / 规避监控 — SQL 注入 + 审计轨迹（CWE-89，L3）
 *
 * 难度：L3（跨方法/跨辅助类：source 经业务方法，调用 AuditRecorder.audit 后再入 sink）。
 *
 * 链路（source→sink）：
 *   1) userInput                                   (source：不可信，来自请求参数)
 *   2) buildSql(userInput)                         (中间节点：拼接 SQL)
 *   3) auditRecorder.audit(sql, callerName)        (跨节点：审计轨迹记录 SQL + 调用方)
 *   4) queryForList(sql)                           (sink：语义等价 JdbcTemplate.queryForList)
 *
 * 为什么是检测压力（区别于现有 SQL 注入样本）：
 *   危险 sink 确实可达（VULN 成立），但 SQL 在进入 sink 前被 AuditRecorder（独立辅助
 *   类）完整写入审计轨迹——包括 SQL 文本与调用方标识。被测对象需额外判断：该注入在
 *   真实运营中会被审计日志记录，攻击可被发现；但漏洞仍在（可达即 VULN），难点是
 *   "规避审计轨迹后才可隐蔽利用"。
 *
 * 修复要点（对照 sec 侧的强制审计模式）：
 *   sec 侧应让审计成为不可绕过约束（审计写入不可由调用方关闭、返回状态不可控），
 *   使注入在运营层面不可隐蔽利用。本 vuln 侧审计仅作观察，判定 VULN。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class DetectionSqlAuditTrail {

    private final AuditRecorder auditRecorder = new AuditRecorder();

    /**
     * 执行用户可控 SQL，执行前经审计记录器记录。
     *
     * @param userInput 用户可控的 SQL 片段
     * @return 查询结果
     */
    public Object query(String userInput) {
        String sql = buildSql(userInput);                       // 中间节点：拼接
        // 跨节点：审计轨迹记录本次 SQL 与调用方（见 AuditRecorder.java:25）
        auditRecorder.audit(sql, "DetectionSqlAuditTrail");
        // [CHECKPOINT id=JSEF-DE-002 cwe=89 level=L3 source=userInput sink=queryForList(sql) semantically JdbcTemplate expect=VULN trace=benchmark/cases/vuln/detection/AuditRecorder.java:25,benchmark/cases/vuln/detection/DetectionSqlAuditTrail.java:39]
        return queryForList(sql);                               // 污点入 sink
    }

    /** 中间节点：把不可信输入拼入 SQL 查询语句。 */
    static String buildSql(String u) {
        return "SELECT * FROM t WHERE name = '" + u + "'";
    }

    // 抽象 sink：语义等价 JdbcTemplate.queryForList(sql)，仅 localhost 打印
    static Object queryForList(String sql) {
        System.out.println("[query] " + sql);
        return java.util.Collections.emptyList();
    }
}
