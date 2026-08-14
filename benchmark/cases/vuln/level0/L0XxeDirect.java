package com.jsef.benchmark.vuln;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

/**
 * JSEF-Benchmark L0 — 基线（XML 外部实体注入，单跳直连）
 *
 * 难度：L0（基线）。source 直接传入 sink，无中间变量。
 * 用于校准 TP 基线与定位精度（CAP-03 入门级）。
 *
 * CWE-611 XML External Entity (XXE)。
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class L0XxeDirect {

    /**
     * 单跳：不可信 XML 直接交给解析器解析（sink），解析器未禁用外部实体。
     *
     * @param xml 不可信 XML 输入
     */
    public void run(DocumentBuilderFactory dbf, String xml) throws Exception {
        DocumentBuilder builder = dbf.newDocumentBuilder();
        // [CHECKPOINT id=JSEF-L0-XXE-001 cwe=611 level=L0 source=untrusted xml sink=DocumentBuilder.parse expect=VULN]
        Document doc = builder.parse(new java.io.ByteArrayInputStream(xml.getBytes()));
    }

    public static void main(String[] args) {
        System.out.println("demo: parse localhost-demo xml");
    }
}
