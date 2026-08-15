// [VULN]
package com.jsef.benchmark.vuln;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;

/**
 * JSEF-Benchmark — 子目标 B2-2：XSLT 注入 (CWE-91，难度 L3)
 *
 * ① 子目标清单：
 *    - 从不可信源（HTTP 参数 / 文件）读取 XSLT 样式表内容；
 *    - 用该未校验内容构造 StreamSource 并传入 TransformerFactory.newTransformer；
 *    - 攻击者可注入恶意 XSLT（如 xsl:include、script、读文件、外部实体）。
 *
 * ② 可达性说明：
 *    不可信源 userStylesheet 经 getStylesheet() 读取（输入读取行），
 *    直接作为 StreamSource 喂给 newTransformer()（sink 行），污染数据流
 *    userStylesheet → StreamSource → TransformerFactory.newTransformer 跨两节点，
 *    故 L3 带 trace=输入读取行,newTransformer 行。
 *
 * ③ 安全底线（仅 localhost 演示，无真实利用脚本）：
 *    仅演示"未校验样式表直接编译"的缺陷语义，不提供真实 XSLT 攻击载荷。
 *
 * ④ 修复要点：
 *    使用固定/受信模板，禁用外部实体与脚本，见 sec/XsltInjection_Safe.java。
 */
public class XsltInjection {

    /**
     * 不可信源：从请求/文件中读取用户提供的 XSLT 样式表（输入读取节点）。
     */
    static String getStylesheet(String userInput) {
        return userInput; // 不可信 XSLT 内容
    }

    /**
     * 危险：用不可信样式表编译 Transformer，未禁用外部实体/脚本。
     */
    static Transformer build(String userInput) throws Exception {
        String sheet = getStylesheet(userInput);
        TransformerFactory factory = TransformerFactory.newInstance();
        // [CHECKPOINT id=JSEF-XSLT-001 cwe=91 level=L3 source=user stylesheet sink=TransformerFactory.newTransformer expect=VULN trace=benchmark/cases/vuln/xslt/XsltInjection.java:36,benchmark/cases/vuln/xslt/XsltInjection.java:45]
        Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(sheet)));
        return transformer;
    }
}
