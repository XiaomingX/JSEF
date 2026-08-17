package com.jsef.benchmark.vuln;

import javax.xml.parsers.DocumentBuilderFactory;

/*
 * JSEF-Benchmark L2 — XML 实体展开拒绝服务 (CWE-776)
 *
 * 难度：L2（多跳）。xml 含多层嵌套 <!ENTITY> 展开（十亿 laughs），
 * DocumentBuilderFactory 未禁用 DTD / 未限制实体展开数，解析即 OOM。
 *
 * 安全底线：仅 localhost 演示语义。
 * 修复要点（XmlBombSafe.java）：setFeature(DISALLOW_DOCTYPE, true)。
 */
public class XmlBombVuln {

    // [CHECKPOINT id=JSEF-NV405 cwe=776 level=L2 source=xml sink=XML parse (entity expansion) expect=VULN]
    public void parseXml(String xml) throws Exception {
        // 未禁用 DTD、未限制实体展开 → 嵌套实体指数展开耗尽内存
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder().parse(new org.xml.sax.InputSource(
                new java.io.StringReader(xml)));
    }
}
