package com.jsef.benchmark.vuln;

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;

/*
 * JSEF-Benchmark L2 — XMLDecoder 反序列化（CWE-502）
 *
 * 难度：L2（多跳）。XMLDecoder.readObject() 会按 XML 内容实例化并调用任意
 * 方法（如 ProcessBuilder），直接解析不可信 XML 即可 RCE。
 *
 * CWE-502 (Deserialization of Untrusted Data)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用 XML。
 *
 * 修复要点（对照 XmlDecoderSafe.java）：不解析不可信 XML（拒绝 / 白名单）。
 */
public class XmlDecoderVuln {

    /**
     * 危险路径：直接反序列化用户 XML。
     *
     * @param userXml 用户可控 XML
     */
    public Object load(String userXml) {
        // [CHECKPOINT id=JSEF-NV104 cwe=502 level=L2 source=userXml sink=XMLDecoder.readObject expect=VULN]
        return new XMLDecoder(new ByteArrayInputStream(userXml.getBytes())).readObject(); // 不可信 XML → 任意方法调用
    }

    public static void main(String[] args) {
        new XmlDecoderVuln().load("<java><object class=\"java.lang.ProcessBuilder\">...</object></java>");
    }
}
