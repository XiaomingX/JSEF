/*
 * JSEF Benchmark 样本 — Log4j ${jndi:} 多跳拼接安全版（CWE-917 / JNDI 注入，长程任务 D 组对照）
 *
 * 修复方式（对照 Log4jConcatLong.java 的 4 个子目标）：
 *   - 拼接前对不可信 host 做 allowlist 校验（仅允许 localhost / 127.0.0.1 / 内网演示地址），
 *     非法 host 直接拒绝，不再进入拼接链；
 *   - 通过校验后虽仍拼接，但 allowlist 已消除 JNDI 远程加载风险；
 *   - 关键安全行：allowlist 校验返回 false 时短路返回，污点在此被截断。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 *
 * 注：独立 benchmark 源文件，不引入真实 log4j 依赖，用模拟方法表达 JndiLookup.lookup 风格 sink。
 *     仅用于静态分析 / LLM 阅读，不强求 mvn 编译。
 */
package com.jsef.benchmark.sec.longtask;

public class Log4jConcatLong_Safe {

    static String jndiLookup(String key) {
        return "resolved:" + key; // SINK（语义，但本样本不会以不可信 host 到达）
    }

    /**
     * 拼接前 allowlist 校验：仅放行受控演示主机，截断不可信污点。
     */
    static boolean isAllowedHost(String host) {
        // [CHECKPOINT id=JSEF-LT-005S cwe=917 level=L5 source=concatenated key sink=sanitized/no-lookup expect=SAFE]
        return host != null && (host.equals("localhost") || host.equals("127.0.0.1") || host.startsWith("127.0.0.1:"));
    }

    static String buildLookupPrefix(String host) {
        return "${jndi:ldap://" + host;
    }

    static String buildPathSegment(String prefix, String suffix) {
        return prefix + "/" + suffix;
    }

    static String assembleLookupKey(String segment) {
        return "${" + segment + "/x}";
    }

    /**
     * 安全入口：host 先经 allowlist 校验，非法即短路；合法（仅演示地址）才拼接。
     */
    static void handleRequest(String host) { // source：不可信主机输入
        if (!isAllowedHost(host)) {
            return; // 阻断：污点在此被截断，不进入拼接链
        }
        String lookupSuffix = "exploit";
        String prefix = buildLookupPrefix(host);
        String segment = buildPathSegment(prefix, lookupSuffix);
        String key = assembleLookupKey(segment);
        jndiLookup(key); // 仅演示地址可达，无 JNDI 远程加载风险
    }

    public static void main(String[] args) {
        handleRequest("127.0.0.1:1389"); // localhost 演示语义
    }
}
