/*
 * JSEF Benchmark 样本 — XXE 未禁用 DTD（D2，CWE-611，L1）
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，使用标准 JDK XML API 表达 sink，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实外部实体利用。
 */
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.xml.sax.InputSource;
import java.io.StringReader;

public class XxeUnsafe {

    /**
     * 危险入口：DocumentBuilderFactory 未禁用 DOCTYPE / 未开启安全处理，解析不可信 XML。
     */
    static Document parse(String xmlInput) throws Exception { // source：不可信 XML 输入
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // [CHECKPOINT id=JSEF-XXE-001 cwe=611 level=L1 source=untrusted xml sink=DocumentBuilder.parse expect=VULN]
        DocumentBuilder db = dbf.newDocumentBuilder();        // 未 setFeature 禁用 DOCTYPE
        return db.parse(new InputSource(new StringReader(xmlInput))); // XXE 可达
    }
}
