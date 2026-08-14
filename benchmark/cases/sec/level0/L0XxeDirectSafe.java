package com.jsef.benchmark.sec;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

/**
 * JSEF-Benchmark L0 — L0XxeDirect 安全对照（SAFE 混淆样本）
 *
 * 安全做法：禁用 DOCTYPE / 外部实体（FEATURE_SECURE_PROCESSING、不展开实体）。
 * 用于计算 TN（正确不报）/ FP（误报）。
 *
 * CWE-611 XML External Entity (XXE)。
 */
public class L0XxeDirectSafe {

    /**
     * 安全解析：解析前关闭外部实体与 DTD。
     *
     * @param xml 不可信 XML 输入
     */
    public void run(DocumentBuilderFactory dbf, String xml) throws Exception {
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        // [CHECKPOINT id=JSEF-L0-XXE-001S cwe=611 level=L0 source=untrusted xml sink=DocumentBuilder.parse expect=SAFE]
        Document doc = builder.parse(new java.io.ByteArrayInputStream(xml.getBytes()));
    }

    public static void main(String[] args) {
        System.out.println("demo: safe parse localhost-demo xml (no external entities)");
    }
}
