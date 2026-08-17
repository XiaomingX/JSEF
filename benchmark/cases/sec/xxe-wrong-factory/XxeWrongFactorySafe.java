package com.jsef.benchmark.sec;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

/*
 * JSEF-Benchmark L3 — XXE 加固修复（CWE-611）
 *
 * 修复：在用于解析的同一 DocumentBuilderFactory 实例上设置 hardening。
 *
 * CWE-611 (Improper Restriction of XML External Entity Reference)。
 */
public class XxeWrongFactorySafe {

    static final String DISALLOW = "http://apache.org/xml/features/disallow-doctype-decl";

    /**
     * 安全路径：加固实例与解析实例一致。
     *
     * @param userXml 用户可控 XML
     */
    public void parse(byte[] userXml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(DISALLOW, true); // 加固设于同一实例
        DocumentBuilder db = dbf.newDocumentBuilder();
        // [CHECKPOINT id=JSEF-NV110S cwe=611 level=L3 source=userXml sink=DocumentBuilder.parse (hardening on same factory instance) expect=SAFE]
        db.parse(new ByteArrayInputStream(userXml)); // 同一实例已禁用 DOCTYPE
    }

    public static void main(String[] args) throws Exception {
        new XxeWrongFactorySafe().parse("<x/>".getBytes());
    }
}
