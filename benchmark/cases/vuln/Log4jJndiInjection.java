/*
 * JSEF Benchmark 样本 — Log4j JNDI 注入（CVE-2021-44228 抽象，B4）
 *
 * 文件头说明：
 *   本样本为独立 benchmark 源文件，不直接依赖真实 log4j 依赖，
 *   用注释 + 模拟方法表达 JndiLookup.lookup 风格的 sink。
 *   仅用于静态分析 / LLM 阅读，不强求 mvn 编译。
 *
 * 漏洞模型（B4，L3 多跳 + 字符串拼接 sink）：
 *   source = 不可信日志输入（HTTP 请求头 / 用户可控日志字段）
 *   taint 经 字段 -> 字符串拼接 -> 日志格式串（含 ${jndi:ldap://...} 子串）
 *   sink  = JndiLookup.lookup 风格调用（由日志框架对格式串做 ${...} 解析触发）
 *
 * 重点：污点被"拼进日志格式串"而非直接传参给 JNDI API ——
 *       这是 Log4j 漏洞区别于普通命令/SQL 注入的关键特征。
 */
public class Log4jJndiInjection {

    /**
     * 模拟 JndiLookup 风格的 sink。
     * 真实场景中由 log4j 在解析日志格式串里的 ${jndi:...} 时调用，
     * 此处用注释表达语义，不引入真实 JNDI 依赖。
     */
    // 真实语义：org.apache.logging.log4j.core.lookup.JndiLookup.lookup(String key)
    static String jndiLookup(String key) {
        // 模拟：JNDI 上下文按 key 中的 ldap:// 地址发起远程加载（仅语义示意，localhost 演示）
        return "resolved:" + key; // SINK（语义）
    }

    /**
     * 模拟 log4j 对日志格式串做 ${...} 子串匹配并分派到 JndiLookup。
     */
    static void logWithFormat(String format) {
        // 简化表达：若 format 含 ${jndi:...} 子串，则取出其中内容交 jndiLookup
        int start = format.indexOf("${jndi:");
        if (start >= 0) {
            int end = format.indexOf('}', start);
            String key = format.substring(start + 2, end); // e.g. jndi:ldap://localhost:1389/evil
            // [CHECKPOINT id=JSEF-LOG4J-001 cwe=917 level=L3 source=untrusted log input sink=JndiLookup.lookup expect=VULN]
            jndiLookup(key); // 污点经拼接进入日志格式串后，在此被 ${} 解析触发
        }
    }

    /**
     * 危险入口：用户可控日志输入直接拼进日志格式串。
     */
    static void handleRequest(String userAgent) { // source：不可信日志输入（如请求头 User-Agent）
        String logPrefix = "[ACCESS] ";
        // 多跳：source -> logPrefix 拼接 -> logFormat（含 ${jndi:...} 子串）
        String logFormat = logPrefix + "client=" + userAgent; // 污点进入格式串
        logWithFormat(logFormat); // sink 经格式串 ${} 解析触发
    }
}
