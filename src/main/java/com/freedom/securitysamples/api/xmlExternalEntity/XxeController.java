package com.freedom.securitysamples.api.xmlExternalEntity;

import org.jdom2.input.sax.SAXHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import javax.xml.parsers.*;
import javax.xml.stream.*;
import org.dom4j.io.SAXReader;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import java.io.*;

@RestController
@RequestMapping("/api")
public class XxeController {

    // 原有的不安全DOM解析示例
    @GetMapping("/xxe/bad01")
    public String processXmlUsingDom(String xmlContent) throws Exception {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        InputStream xmlInputStream = new ByteArrayInputStream(xmlContent.getBytes());
        Document document = documentBuilder.parse(xmlInputStream);
        return "success";
    }

    // 原有的不安全SAX解析示例
    @GetMapping("/xxe/bad02")
    public String processXmlUsingSax(String xmlContent) throws Exception {
        SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
        SAXParser saxParser = saxParserFactory.newSAXParser();
        SAXHandler saxHandler = new SAXHandler();
        saxParser.parse(xmlContent, saxHandler);
        return "success";
    }

    // 新增:不安全的DOM4J解析示例
    @GetMapping("/xxe/bad03")
    public String processXmlUsingDom4j(String xmlContent) throws Exception {
        SAXReader saxReader = new SAXReader();
        InputStream inputStream = new ByteArrayInputStream(xmlContent.getBytes());
        org.dom4j.Document document = saxReader.read(inputStream);
        return "success";
    }

    // 新增:不安全的StAX解析示例
    @GetMapping("/xxe/bad04")
    public String processXmlUsingStax(String xmlContent) throws Exception {
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        StringReader stringReader = new StringReader(xmlContent);
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(stringReader);
        while(xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
        return "success";
    }

    // 新增:不安全的Transformer示例
    @GetMapping("/xxe/bad05")
    public String processXmlUsingTransformer(String xmlContent) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        StreamSource source = new StreamSource(new StringReader(xmlContent));
        transformer.transform(source, null);
        return "success";
    }

    // 新增:不安全的XMLReader示例
    @GetMapping("/xxe/bad06")
    public String processXmlUsingXMLReader(String xmlContent) throws Exception {
        XMLReader xmlReader = XMLReaderFactory.createXMLReader();
        StringReader stringReader = new StringReader(xmlContent);
        InputSource inputSource = new InputSource(stringReader);
        xmlReader.parse(inputSource);
        return "success";
    }

    // 新增:不安全的DocumentBuilder带参数示例
    @GetMapping("/xxe/bad07")
    public String processXmlUsingDomWithParams(String xmlContent) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setValidating(true);
        dbf.setNamespaceAware(true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        InputStream inputStream = new ByteArrayInputStream(xmlContent.getBytes());
        Document doc = builder.parse(inputStream);
        return "success";
    }
}