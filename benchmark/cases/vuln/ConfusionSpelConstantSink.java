/*
 * JSEF Benchmark 真假混淆样本 — SpEL 常量 sink（B5，CWE-917）
 * VULN 版：用户输入拼进 SpEL 表达式。
 * 文件头说明：独立 benchmark 源文件，使用模拟 SpelExpressionParser 表达 sink，不强求编译。
 */
public class ConfusionSpelConstantSink {

    static Object parseExpression(String expr) {
        // 模拟：org.springframework.expression.spel.standard.SpelExpressionParser.parseExpression
        return expr; // SINK（语义）
    }

    /**
     * 危险入口：用户输入被拼进 SpEL 表达式文本。
     */
    static Object unsafe(String userInput) { // source：不可信用户输入
        String expr = "T(java.lang.Runtime).getRuntime().exec('" + userInput + "')";
        // [CHECKPOINT id=JSEF-CONF-SPEL-001 cwe=917 level=L1 source=user input sink=spelParser.parseExpression expect=VULN]
        return parseExpression(expr); // 用户可控表达式被解析执行
    }
}
