package com.jsef.benchmark.sec;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;

/*
 * JSEF-Benchmark L3 — SVG XXE 修复（CWE-611）
 *
 * 修复：在用于解析的同一 DocumentBuilderFactory 上禁用 DOCTYPE 声明。
 *
 * CWE-611 (Improper Restriction of XML External Entity Reference)。
 */
public class SvgXxeSafe {

    static final String DISALLOW = "http://apache.org/xml/features/disallow-doctype-decl";

    /**
     * 安全路径：禁用 DOCTYPE。
     *
     * @param svgBytes 用户可控 SVG 字节
     */
    public void parse(byte[] svgBytes) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(DISALLOW, true); // 禁用 DOCTYPE → 阻断 XXE
        DocumentBuilder db = dbf.newDocumentBuilder();
        // [CHECKPOINT id=JSEF-NV109S cwe=611 level=L3 source=svgBytes sink=DocumentBuilder.parse (XXE blocked by disallow-doctype-decl) expect=SAFE]
        db.parse(new ByteArrayInputStream(svgBytes)); // 外部实体被禁
    }

    public static void main(String[] args) throws Exception {
        new SvgXxeSafe().parse("<svg/>".getBytes());
    }
}
