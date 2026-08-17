package com.jsef.benchmark.vuln;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

/*
 * JSEF-Benchmark L3 — SVG XXE（CWE-611）
 *
 * 难度：L3（跨方法 / 间接）。SVG 本质是 XML，未禁用 DOCTYPE 时可在 SVG 内
 * 嵌外部实体引用，读取本地文件 / 发起 SSRF。此处 DocumentBuilderFactory
 * 使用默认配置（未禁用 DOCTYPE）。
 *
 * CWE-611 (Improper Restriction of XML External Entity Reference)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用 SVG。
 *
 * 修复要点（对照 SvgXxeSafe.java）：setFeature(DISALLOW_DOCTYPE_DECL, true)。
 */
public class SvgXxeVuln {

    /**
     * 危险路径：默认解析 SVG，未禁 DOCTYPE。
     *
     * @param svgBytes 用户可控 SVG 字节
     */
    public void parse(byte[] svgBytes) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); // 默认配置：DOCTYPE 未禁
        DocumentBuilder db = dbf.newDocumentBuilder();
        // [CHECKPOINT id=JSEF-NV109 cwe=611 level=L3 source=svgBytes sink=DocumentBuilder.parse (XXE via SVG) expect=VULN]
        db.parse(new ByteArrayInputStream(svgBytes)); // 未禁外部实体 → XXE
    }

    public static void main(String[] args) throws Exception {
        new SvgXxeVuln().parse("<svg><!ENTITY xxe SYSTEM \"file:///etc/passwd\">></svg>".getBytes());
    }
}
