package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L4 — 活分支消毒截断（switch 多分支，仅 default 参数化）
 *
 * 难度：L4（多分支状态分发 + 部分参数化）。`switch(param.getType())` 的 CASE A/B/C
 * 分支都把 value 拼进 SQL 语句（真正可达 sink），仅 default 分支用 PreparedStatement
 * 参数化。被测对象若只看到“存在参数化 / default 安全路径”就报 SAFE，会漏报 CASE 分支
 * 的注入（过早下结论）；反之若只看到“有 executeQuery sink”就对所有分支报 VULN，
 * 会误报 default 分支（FP）。
 *
 * 与 case-bypass/confusion（假消毒/名字混淆，污点实际没被截断）不同：default 分支的
 * 参数化是真实生效的（该分支 SAFE），但其他活 case 分支的拼串未消毒——这是“真消毒在
 * 某条活路径生效、另一条活路径仍然 VULN”。
 *
 * CWE-89 (SQL Injection)。安全底线：仅 localhost 演示语义。
 *
 * 修复要点（对照 FullSwitchTypeSql.java）：所有 case 分支（含 default）一律参数化，
 * 用 PreparedStatement 绑定参数，不按 type 拼 SQL。
 */
public class SwitchTypeSql {

    /**
     * 按类型分派拼接/参数化 SQL。
     *
     * @param param 请求对象（含可控 type 与 value）
     */
    public void query(Request param) {
        switch (param.getType()) {                                     // 分支判定行（trace 节点 1）
            case "A":
                execute("SELECT * FROM a WHERE k = '" + param.getValue() + "'");  // 拼 SQL → 可达 sink
                break;
            case "B":
                // [CHECKPOINT id=JSEF-DEAD-002 cwe=89 level=L4 source=param.getValue sink=Statement.executeQuery (case B, unsanitized concat) expect=VULN trace=benchmark/cases/vuln/branch-dead-end/SwitchTypeSql.java:29,benchmark/cases/vuln/branch-dead-end/SwitchTypeSql.java:35]
                execute("SELECT * FROM b WHERE k = '" + param.getValue() + "'");  // 拼 SQL → 可达 sink（checkpoint）
                break;
            case "C":
                execute("SELECT * FROM c WHERE k = '" + param.getValue() + "'");  // 拼 SQL → 可达 sink
                break;
            default:
                executeParam("SELECT * FROM d WHERE k = ?", param.getValue());    // default：参数化，安全
        }
    }

    // 抽象 sink：语义等价 Statement.executeQuery(sql)，仅 localhost 打印
    static void execute(String sql) {
        System.out.println("[sql-exec] " + sql);
    }

    // 抽象安全 sink：语义等价 PreparedStatement.executeQuery(sql, param)
    static void executeParam(String sql, String v) {
        System.out.println("[sql-exec-safe] " + sql + " param=" + v);
    }

    static class Request {
        private final String type;
        private final String value;

        Request(String type, String value) {
            this.type = type;
            this.value = value;
        }

        String getType() {
            return type;
        }

        String getValue() {
            return value;
        }
    }

    public static void main(String[] args) {
        new SwitchTypeSql().query(new Request("B", "x' OR '1'='1"));
    }
}
