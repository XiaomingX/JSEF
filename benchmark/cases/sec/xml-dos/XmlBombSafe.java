package com.jsef.benchmark.sec;

import javax.xml.parsers.DocumentBuilderFactory;

/*
 * JSEF-Benchmark L2 — XML 实体展开拒绝服务修复 (CWE-776) expect=SAFE
 *
 * sec 侧：禁用 DOCTYPE 声明（彻底阻断外部/内部实体）、并限制实体展开数为 0，
 * 嵌套实体无法展开，解析安全。
 *
 * 安全底线：按实现判定为安全。
 */
public class XmlBombSafe {

    static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";

    // [CHECKPOINT id=JSEF-NV405S cwe=776 level=L2 source=xml sink=XML parse (doctype disallowed) expect=SAFE]
    public void parseXml(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // 禁用 DTD → 嵌套实体无法声明与展开
        dbf.setFeature(DISALLOW_DOCTYPE, true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.newDocumentBuilder().parse(new org.xml.sax.InputSource(
                new java.io.StringReader(xml)));
    }
}
