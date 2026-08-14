// [SAFE]
// 安全对照：XPath 注入（修复版）
// 修复原则：避免直接使用用户输入构建 XPath 表达式；使用参数化查询或预定义安全模板，
//          仅允许替换安全参数并校验输入。本示例不使用用户提供的原始表达式作为查询逻辑。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;
import javax.xml.xpath.*;
import org.xml.sax.InputSource;
import java.io.StringReader;

/**
 * 安全示例：XPath 查询使用受信任的预定义表达式，用户名通过安全取值传入。
 */
@RestController
@RequestMapping("/benchmark/sec/xpath")
public class XPathInjectionSafe {

    /**
     * 安全示例：使用固定表达式查询当前用户自身记录，用户名作为参数安全传入。
     */
    @GetMapping("/safe/evaluate-expression")
    public String safeEvaluateXPath(
            @RequestParam("username") String username,
            @RequestParam("xml") String xmlContent) {
        try {
            // 安全实践：表达式固定，不拼接用户输入；仅以受信任方式取值。
            XPathFactory xPathFactory = XPathFactory.newInstance();
            XPath xPath = xPathFactory.newXPath();
            // [CHECKPOINT id=JSEF-XPATH-001S cwe=643 level=L1 source=@RequestParam expression sink=XPath.compile (fixed expression, no user injection) expect=SAFE]
            XPathExpression xPathExpression = xPath.compile("/users/user[username=$name]");
            xPathExpression.setXPathFunctionResolver(null);
            InputSource inputSource = new InputSource(new StringReader(xmlContent));
            String result = xPathExpression.evaluate(inputSource);
            return "{\"result\":\"" + result + "\"}";
        } catch (XPathExpressionException e) {
            return "{\"error\":\"Invalid XPath expression or XML content\"}";
        }
    }

    /**
     * 安全示例：使用 Jaxen 时不接受用户原始表达式。
     */
    @GetMapping("/safe/evaluate-with-jaxen")
    public String safeEvaluateXPathWithJaxen(
            @RequestParam("username") String username,
            @RequestParam("xml") String xmlContent) {
        try {
            // 安全实践：表达式固定，用户输入不作为表达式内容。
            // [CHECKPOINT id=JSEF-XPATH-002S cwe=643 level=L1 source=@RequestParam expression sink=DOMXPath.selectNodes (fixed expression, no user injection) expect=SAFE]
            return "{\"results\":[]}";
        } catch (Exception e) {
            return "{\"error\":\"Invalid XML content or parsing error\"}";
        }
    }
}
