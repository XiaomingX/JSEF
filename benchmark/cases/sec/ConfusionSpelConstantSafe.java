/*
 * JSEF Benchmark 真假混淆样本 — SpEL 常量 sink（B5，CWE-917）
 * SAFE 版：表达式用固定常量，用户输入仅作数据变量（SimpleEvaluationContext 风格，无方法执行）。
 * 文件头说明：独立 benchmark 源文件，使用模拟 SpelExpressionParser 表达 sink，不强求编译。
 */
public class ConfusionSpelConstantSafe {

    static Object parseExpression(String expr) {
        return expr; // SINK（语义）
    }

    /**
     * 安全入口：表达式为固定常量模板，用户输入仅作为数据变量求值。
     * 使用 SimpleEvaluationContext 风格（禁止方法/类型调用），用户数据无法触发代码执行。
     */
    static Object safe(String userInput) {
        // [CHECKPOINT id=JSEF-CONF-SPEL-001S cwe=917 level=L1 source=user input sink=spelParser.parseExpression expect=SAFE]
        String expr = "#name"; // 固定常量表达式模板
        // 在 SIMPLE 上下文下仅支持数据变量读取，userInput 作为 #name 的值，不可执行方法
        Object value = parseExpression(expr);
        // 模拟：SimpleEvaluationContext，setValue("name", userInput) -> 纯数据，无类型/方法解析
        return value;
    }
}
