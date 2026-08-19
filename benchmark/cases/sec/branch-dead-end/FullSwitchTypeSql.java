package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L4 — FullSwitchTypeSql 安全对照（所有分支均参数化）
 *
 * 安全做法：与 SwitchTypeSql 相同的 switch 结构，但所有 case 分支（A/B/C/default）
 * 都使用 PreparedStatement 参数化，不按 type 拼 SQL——无注入可能。用于计算 TN / FP。
 *
 * CWE-89 (SQL Injection)。安全底线：仅 localhost 演示语义。
 */
public class FullSwitchTypeSql {

    /**
     * 所有分支均参数化查询。
     *
     * @param param 请求对象（含可控 type 与 value）
     */
    public void query(Request param) {
        switch (param.getType()) {
            case "A":
                executeParam("SELECT * FROM a WHERE k = ?", param.getValue());
                break;
            case "B":
                executeParam("SELECT * FROM b WHERE k = ?", param.getValue());
                break;
            case "C":
                executeParam("SELECT * FROM c WHERE k = ?", param.getValue());
                break;
            default:
                // [CHECKPOINT id=JSEF-DEAD-002S cwe=89 level=L4 source=param.getValue sink=PreparedStatement.executeQuery (all branches parameterized) expect=SAFE]
                executeParam("SELECT * FROM d WHERE k = ?", param.getValue());   // 参数化安全 sink → SAFE
        }
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
        new FullSwitchTypeSql().query(new Request("B", "x' OR '1'='1"));
    }
}
