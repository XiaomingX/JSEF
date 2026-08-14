package com.jsef.benchmark.sec;

import java.util.function.Function;

/**
 * JSEF-Benchmark L5 — GadgetChainXxe 安全对照（SAFE 混淆样本）
 *
 * 安全做法：链末端（或最早节点）设置 disallow-doctype-decl=true，且后续包装/解析不再覆盖该开关，
 * 不可信 XML 进入解析器时外部实体已被禁止。用于计算 TN / FP。
 *
 * CWE-611。
 */
public class GadgetChainXxeSafe {

    @FunctionalInterface
    interface SafeWrapper extends Function<String, String> {
    }

    static String read(String raw) {
        return raw;
    }

    /** 安全开关：禁止 DOCTYPE 声明（外部实体彻底关闭）。 */
    static boolean disallowDoctype() {
        return true; // 链末端不再被覆盖
    }

    static SafeWrapper envelop() {
        return xml -> "<envelope>" + xml + "</envelope>";
    }

    static String parseSafe(String xml, boolean disallow) {
        // 语义等价：factory.setFeature("...disallow-doctype-decl", true); reader.read(xml)
        if (disallow) {
            System.out.println("[xxe-safe] doctype disallowed, external entities off");
            return "parsed-safe:" + xml;
        }
        return "parsed:" + xml;
    }

    public static String buildSafeChain(String untrustedXml) {
        SafeWrapper chain = ignored -> {
            String xml = read(untrustedXml);       // 输入读取
            xml = envelop().apply(xml);            // 包裹
            boolean disallow = disallowDoctype();  // 链路固定禁止 DOCTYPE
            // [CHECKPOINT id=JSEF-L5-XXE-001S cwe=611 level=L5 source=untrusted xml sink=SAXReader.read expect=SAFE]
            return parseSafe(xml, disallow); // 不可信 XML 进入时已禁外部实体
        };
        return chain.apply("ignored");
    }

    public static void main(String[] args) {
        buildSafeChain("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">");
    }
}
