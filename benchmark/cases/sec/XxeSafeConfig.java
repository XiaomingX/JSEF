/*
 * JSEF Benchmark 真假混淆样本 — XXE 安全配置（D2，CWE-611，L3）
 * SAFE 版：显式禁用 DOCTYPE 声明（disallow-doctype-decl）并开启 FEATURE_SECURE_PROCESSING。
 * 测试点：弱 SAST/LLM 易将"解析 XML + 用户输入"误报为 XXE（测 FP）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.XMLConstants;
import org.xml.sax.InputSource;
import java.io.StringReader;

public class XxeSafeConfig {

    /**
     * 安全入口：先加固 parser 再解析。
     */
    static Document safeParse(String xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // 禁用外部实体 / DOCTYPE —— 关键防护
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        // [CHECKPOINT id=JSEF-XXE-001S cwe=611 level=L3 source=untrusted xml sink=DocumentBuilder.parse expect=SAFE]
        DocumentBuilder db = dbf.newDocumentBuilder();       // 已加固，无 XXE
        return db.parse(new InputSource(new StringReader(xmlInput)));
    }
}
