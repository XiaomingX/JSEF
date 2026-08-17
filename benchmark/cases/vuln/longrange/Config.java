package com.jsef.benchmark.vuln.longrange;

/**
 * JSEF-Benchmark L5 长程链路 1 — config 模块（CWE-917 SpEL 表达式注入）
 *
 * 角色：模拟真实库的"配置加载层"。从不可信 HTTP 请求体（JSON/YAML）里
 * 取出一个 {@code expression} 字段，封装成一个配置对象交给下游。
 *
 * 污点流入：不可信 HTTP 请求体（攻击者控制）中的 expression 字符串。
 * 污点流出：AppConfig.expression 字段（未经验证直接携带不可信表达式文本）。
 *
 * 安全底线：仅 localhost 演示，不写真实利用载荷。
 */
public class Config {

    /** 封装从不可信请求体解析出的应用配置。 */
    public static class AppConfig {
        private final String expression;
        private final String dataSourceName;

        public AppConfig(String expression, String dataSourceName) {
            // 污点流入点：expression 直接来自不可信请求体，未做任何白名单/校验
            this.expression = expression;
            this.dataSourceName = dataSourceName;
        }

        public String getExpression() {
            return expression; // 污点从这里流出到解析模块
        }

        public String getDataSourceName() {
            return dataSourceName;
        }
    }

    /**
     * 模拟"配置加载器"：把不可信请求体解析成 AppConfig。
     * 真实库常用 Jackson / SnakeYAML 读配置；此处用语义桩代替，
     * 仅演示"不可信文本被当作合法的配置项收下"这一语义。
     *
     * @param requestBody 不可信 HTTP 请求体（攻击者完全控制）
     * @return 携带不可信 expression 的配置对象
     */
    public AppConfig loadConfig(String requestBody) {
        // 语义等价：Jackson ObjectMapper.readValue(requestBody, AppConfig.class)
        // 或 SnakeYAML 解析 YAML —— 仅把请求体里的 expression 字段原样取出
        String expression = extractField(requestBody, "expression"); // 中间传递点 1
        String dsName = extractField(requestBody, "dataSource");     // 中间传递点 2（无害）
        return new AppConfig(expression, dsName);
    }

    /** 从请求体按 key 取字段（语义桩：真实库为 JSON/YAML 解析）。 */
    static String extractField(String body, String key) {
        // 语义等价：JsonNode.get(key).asText()
        int idx = body.indexOf("\"" + key + "\"");
        if (idx < 0) {
            return "";
        }
        int colon = body.indexOf(':', idx);
        int q1 = body.indexOf('"', colon);
        int q2 = body.indexOf('"', q1 + 1);
        return q1 < 0 || q2 < 0 ? "" : body.substring(q1 + 1, q2);
    }
}
