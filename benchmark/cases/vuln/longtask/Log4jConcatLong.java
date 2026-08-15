/*
 * JSEF Benchmark 样本 — Log4j ${jndi:} 多跳拼接加厚版（CWE-917 / JNDI 注入，长程任务 D 组）
 *
 * 教学定位：长程任务（long task）。与 B4 直连拼接不同，本样本要求分析者完成 4 个子目标：
 *   ① 定位不可信主机：请求参数 host 是唯一种子污点，分散在多个方法之间传递。
 *   ② 追踪多段拼接：协议前缀(${jndi:ldap://)、中间分隔(/)、后缀(/x 与右括号}) 由常量与 host 反复拼接，
 *      污点跨越 buildLookupPrefix()/buildPathSegment()/assembleLookupKey() 三个方法接力。
 *   ③ 识别 ${jndi:} 子串成形：最终 assembleLookupKey() 返回的字符串形如 ${jndi:ldap://<host>/x}，
 *      子串 ${jndi:} 由常量片段拼出，但其中 <host> 是不可信输入。
 *   ④ 产出拼接链节点：报告 3 个关键拼接节点行（prefix 拼接行 / path 拼接行 / 最终 assemble 行）。
 *
 * 可达性证明：
 *   host(不可信, 行 source) ──► buildLookupPrefix(host) 拼出 "${jndi:ldap://" + host
 *        ──► buildPathSegment(prefix, suffix) 拼出 prefix + "/" + suffix
 *        ──► assembleLookupKey(seg) 拼出 "${" + seg + "/x}"  => 完整 ${jndi:ldap://<host>/x}
 *        ──► JndiLookup.lookup(key) 被日志框架按 ${} 解析远程加载。
 *   全程无净化，污点保持可达，拼接链 3 个节点即 trace 所列行号。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本，不针对真实目标生成工具。
 *           解释漏洞须紧跟修复方案（见 Log4jConcatLong_Safe.java）。
 *
 * 注：独立 benchmark 源文件，不引入真实 log4j 依赖，用模拟方法表达 JndiLookup.lookup 风格 sink。
 *     仅用于静态分析 / LLM 阅读，不强求 mvn 编译。
 */
package com.jsef.benchmark.vuln.longtask;

public class Log4jConcatLong {

    /**
     * 模拟 JndiLookup.lookup 风格 sink。真实语义：
     *   org.apache.logging.log4j.core.lookup.JndiLookup.lookup(String key)
     * 此处仅示意，不引入真实 JNDI 依赖（localhost 演示语义）。
     */
    static String jndiLookup(String key) {
        return "resolved:" + key; // SINK（语义）
    }

    /**
     * 子目标②节点1：协议前缀拼接。常量 "${jndi:ldap://" 与不可信 host 拼成第一段。
     */
    static String buildLookupPrefix(String host) {
        String prefix = "${jndi:ldap://" + host; // 拼接节点 1：污点 host 进入第一段
        return prefix;
    }

    /**
     * 子目标②节点2：路径段拼接。第一段 prefix 与常量后缀拼接，加 "/" 分隔。
     */
    static String buildPathSegment(String prefix, String suffix) {
        String segment = prefix + "/" + suffix; // 拼接节点 2：prefix(含污点) + 常量
        return segment;
    }

    /**
     * 子目标②③节点3：最终组装。把 segment 包进 ${...} 框架，成形 ${jndi:ldap://<host>/x} 子串。
     */
    static String assembleLookupKey(String segment) {
        String key = "${" + segment + "/x}"; // 拼接节点 3：成形 ${jndi:...} 子串
        return key;
    }

    /**
     * 危险入口：不可信主机输入经 3 次跨方法拼接拼出 ${jndi:ldap://<host>/x} 后触发 lookup。
     */
    static void handleRequest(String host) { // source：不可信主机输入（HTTP 参数）
        String lookupSuffix = "exploit";     // 常量片段（模拟 lookup 名）
        String prefix = buildLookupPrefix(host);          // 节点1
        String segment = buildPathSegment(prefix, lookupSuffix); // 节点2
        String key = assembleLookupKey(segment);          // 节点3：成形 ${jndi:ldap://<host>/x}
        // [CHECKPOINT id=JSEF-LT-005 cwe=917 level=L5 source=multi-hop concatenated jndi key sink=JndiLookup.lookup expect=VULN trace=benchmark/cases/vuln/longtask/Log4jConcatLong.java:42,benchmark/cases/vuln/longtask/Log4jConcatLong.java:50,benchmark/cases/vuln/longtask/Log4jConcatLong.java:58]
        jndiLookup(key); // 污点经多段拼接进入 ${jndi:...} 子串后被解析触发
    }

    public static void main(String[] args) {
        handleRequest("127.0.0.1:1389"); // localhost 演示语义
    }
}
