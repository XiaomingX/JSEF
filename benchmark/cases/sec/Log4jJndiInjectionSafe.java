/*
 * JSEF Benchmark 样本 — Log4j JNDI 注入安全版（B4，expect=SAFE）
 *
 * 修复方式：
 *   1) 使用参数化日志 logger.info("user: {}", userInput)，用户数据作为纯参数，
 *      不进入日志格式串，因此不会参与 ${jndi:...} 子串解析；
 *   2) 或对格式串做 message 改写，去除 ${} 占位符。
 *
 * 文件头说明：独立 benchmark 源文件，不引入真实 log4j 依赖，用模拟方法表达语义。
 */
public class Log4jJndiInjectionSafe {

    static String jndiLookup(String key) {
        return "resolved:" + key;
    }

    /**
     * 安全日志封装：用户数据作为占位符参数，而非拼进格式串。
     */
    static void logWithFormat(String format, Object... args) {
        // 参数化：格式串为常量，args 仅作数据填充，不会触发 ${} 解析
        String resolved = format;
        for (Object a : args) {
            resolved = resolved.replaceFirst("\\{}", String.valueOf(a));
        }
        int start = resolved.indexOf("${jndi:");
        if (start >= 0) {
            int end = resolved.indexOf('}', start);
            String key = resolved.substring(start + 2, end);
            jndiLookup(key);
        }
    }

    /**
     * 安全入口：参数化日志（非拼接）。
     */
    static void handleRequest(String userAgent) {
        // [CHECKPOINT id=JSEF-LOG4J-001S cwe=917 level=L3 source=untrusted log input sink=JndiLookup.lookup expect=SAFE]
        logWithFormat("[ACCESS] client={}", userAgent); // userAgent 不进入格式串，无 JNDI 触发
    }
}
