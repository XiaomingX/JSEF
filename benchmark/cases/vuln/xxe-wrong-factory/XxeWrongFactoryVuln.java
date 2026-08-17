package com.jsef.benchmark.vuln;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

/*
 * JSEF-Benchmark L3 — XXE 加固用错 Factory 实例（CWE-611）
 *
 * 难度：L3（跨方法 / 实例错配）。开发者在 factory a 上设置了
 * disallow-doctype-decl，但实际解析使用的是另一个全新且未加固的 factory b，
 * 加固对真正用于解析的实例无效，XXE 仍然存在。
 *
 * CWE-611 (Improper Restriction of XML External Entity Reference)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用 XML。
 *
 * 修复要点（对照 XxeWrongFactorySafe.java）：加固设于用于解析的同一实例。
 */
public class XxeWrongFactoryVuln {

    static final String DISALLOW = "http://apache.org/xml/features/disallow-doctype-decl";

    /**
     * 危险路径：加固实例与解析实例不一致。
     *
     * @param userXml 用户可控 XML
     */
    public void parse(byte[] userXml) throws Exception {
        DocumentBuilderFactory a = DocumentBuilderFactory.newInstance();
        a.setFeature(DISALLOW, true); // 加固在 a 上——但解析没用它
        DocumentBuilderFactory b = DocumentBuilderFactory.newInstance(); // 全新、未加固
        DocumentBuilder db = b.newDocumentBuilder();
        // [CHECKPOINT id=JSEF-NV110 cwe=611 level=L3 source=userXml sink=DocumentBuilder.parse (hardening on wrong factory instance) expect=VULN]
        db.parse(new ByteArrayInputStream(userXml)); // 用未加固的 b 解析 → XXE 仍可达
    }

    public static void main(String[] args) throws Exception {
        new XxeWrongFactoryVuln().parse("<!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x/>".getBytes());
    }
}
