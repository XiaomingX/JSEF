package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L3 — XStream allowlist 顺序错误（CWE-502）
 *
 * 难度：L3（跨方法 / 顺序依赖）。正确做法须先设 allowTypes 再 fromXML；
 * 此处先 fromXML 解析（此时仍按默认无限制映射），再设置 allowTypes，
 * 导致 allowlist 对已解析对象无效，攻击载荷已实例化。
 *
 * CWE-502 (Deserialization of Untrusted Data)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用 XML。
 *
 * 修复要点（对照 XstreamLateAllowlistSafe.java）：先 allowTypes 再 fromXML。
 */
public class XstreamLateAllowlistVuln {

    // 抽象 sink：语义等价 com.thoughtworks.xstream.XStream.fromXML(xml)
    static Object fromXml(String xml) {
        System.out.println("[xstream-fromxml] " + xml);
        return null;
    }

    static void allowTypes(Class<?>... types) { /* 设置白名单 */ }

    /**
     * 危险路径：先解析后设白名单，白名单失效。
     *
     * @param xml 用户可控 XML
     */
    public Object parse(String xml) {
        // [CHECKPOINT id=JSEF-NV105 cwe=502 level=L3 source=userXml sink=XStream.fromXML (allowlist AFTER parse) expect=VULN]
        Object obj = fromXml(xml); // 先解析：此时无白名单保护
        allowTypes(SafeDto.class); // 后设白名单：对已解析对象无效
        return obj;
    }

    static class SafeDto {}

    public static void main(String[] args) {
        new XstreamLateAllowlistVuln().parse("<map><entry>x</entry></map>");
    }
}
