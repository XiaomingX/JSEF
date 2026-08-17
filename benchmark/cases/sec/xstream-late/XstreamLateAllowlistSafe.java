package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L3 — XStream allowlist 顺序修复（CWE-502）
 *
 * 修复：先设置 allowTypes 白名单，再执行 fromXML，确保解析受白名单约束。
 *
 * CWE-502 (Deserialization of Untrusted Data)。
 */
public class XstreamLateAllowlistSafe {

    static Object fromXml(String xml) {
        System.out.println("[xstream-fromxml] " + xml);
        return null;
    }

    static void allowTypes(Class<?>... types) { /* 设置白名单 */ }

    /**
     * 安全路径：先 allowTypes 再 fromXML。
     *
     * @param xml 用户可控 XML
     */
    public Object parse(String xml) {
        allowTypes(SafeDto.class); // 先设白名单
        // [CHECKPOINT id=JSEF-NV105S cwe=502 level=L3 source=userXml sink=XStream.fromXML (allowlist BEFORE parse) expect=SAFE]
        return fromXml(xml); // 解析时白名单已生效
    }

    static class SafeDto {}

    public static void main(String[] args) {
        new XstreamLateAllowlistSafe().parse("<SafeDto/>");
    }
}
