// [VULN]
package com.jsef.benchmark.sec;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;

/**
 * JSEF-Benchmark — 子目标 B2-2 安全对照：XSLT 固定受信模板 (CWE-91，SAFE)
 *
 * ① 子目标清单：
 *    - 使用编译期固定、经过评审的 XSLT 模板（不取自用户输入）；
 *    - 关闭 TransformerFactory 的危险特性（外部实体 / 样式表/脚本访问）。
 *
 * ② 可达性说明：
 *    模板为硬编码常量 TRUSTED_XSLT，与 userInput 无数据流关联，
 *    sink newTransformer 仅接收受信内容 → 不可达注入。
 *
 * ③ 安全底线（仅 localhost 演示，无真实利用脚本）：
 *    仅演示安全写法，不提供任何攻击脚本。
 *
 * ④ 修复要点：
 *    固定模板 + 关闭 SECURE_PROCESSING / ACCESS_EXTERNAL_* 特性。
 */
public class XsltInjection_Safe {

    // 受信模板：编译期固定，不由用户输入决定
    private static final String TRUSTED_XSLT =
        "<xsl:stylesheet version='1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform'>"
        + "<xsl:template match='/'><root/></xsl:template></xsl:stylesheet>";

    /**
     * 安全：使用固定受信模板，且关闭危险特性。
     */
    static Transformer build() throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        // 禁用外部实体 / 外部样式表 / 脚本访问
        try {
            factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
            factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalStylesheet", "");
        } catch (Exception ignored) { /* 部分实现不支持属性名，靠 SECURE_PROCESSING */ }
        factory.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // [CHECKPOINT id=JSEF-XSLT-001S cwe=91 level=L3 source=trusted constant sink=TransformerFactory.newTransformer expect=SAFE]
        Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(TRUSTED_XSLT)));
        return transformer;
    }
}
