package com.jsef.benchmark.vuln;

import java.util.function.Function;

/**
 * JSEF-Benchmark L5 — gadget chain（CWE-611 XXE）
 *
 * 多个"单独安全"的包装器按序组合，把不可信 XML 送入开启外部实体解析的解析器：
 *   - InputReader     ~ 读取输入为字符串（无害）
 *   - EntitySwitch    ~ 配置实体解析开关（看似安全：默认开启以"兼容旧系统"）
 *   - Wrapper         ~ 把 XML 包进外层 envelope（无害，纯包裹）
 *   - XmlParser       ~ 最终解析（危险：外部实体解析开启）
 *
 * 关键点（L5 难度）：EntitySwitch 单看是"为兼容开启"的无害配置，Wrapper 也是无害包裹，
 * 但组合后不可信 XML 经多个包装器最终进入"外部实体解析开启"的解析器，触发 XXE。
 * 每个节点单独无害，跨节点组合才危险。
 *
 * 安全底线：本文件仅演示链式可达性语义，仅 localhost 演示，不提供真实利用载荷。
 *
 * CWE-611。
 */
public class GadgetChainXxe {

    @FunctionalInterface
    interface Wrapper extends Function<String, String> {
    }

    /** 输入读取器（无害，纯读取）。 */
    static String read(String raw) {
        return raw;
    }

    /** 实体解析开关配置器（看似安全：默认开启以兼容）。 */
    static boolean externalEntitiesEnabled() {
        return true; // 兼容旧系统而开启外部实体
    }

    /** 包装器（无害，纯包裹）。 */
    static Wrapper envelop() {
        return xml -> "<envelope>" + xml + "</envelope>";
    }

    /** 危险处理器：解析开启外部实体的 XML（不可信入 sink）。 */
    static Wrapper xmlParser() {
        return xml -> {
            boolean ext = externalEntitiesEnabled(); // 外部实体解析开启
            // [CHECKPOINT id=JSEF-L5-XXE-001 cwe=611 level=L5 source=untrusted xml sink=SAXReader.read expect=VULN trace=benchmark/cases/vuln/level5/GadgetChainXxe.java:63,benchmark/cases/vuln/level5/GadgetChainXxe.java:64,benchmark/cases/vuln/level5/GadgetChainXxe.java:65,benchmark/cases/vuln/level5/GadgetChainXxe.java:43]
            return parse(xml, ext); // 不可信 XML 触发外部实体解析
        };
    }

    static String parse(String xml, boolean external) {
        // 语义等价：new SAXReader(); reader.setFeature(..., !external); reader.read(xml)
        System.out.println("[xxe-parse] externalEntities=" + external + " xml=" + xml);
        return "parsed:" + xml;
    }

    /**
     * 构造危险 gadget chain：不可信 XML 经读取→开关开启→包裹→解析。
     */
    public static String buildAndTrigger(String untrustedXml) {
        Wrapper chain = ignored -> {
            String xml = read(untrustedXml);      // 输入读取
            xml = envelop().apply(xml);           // 包裹
            return xmlParser().apply(xml);        // 末端 sink
        };
        return chain.apply("ignored");
    }

    public static void main(String[] args) {
        buildAndTrigger("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">");
    }
}
