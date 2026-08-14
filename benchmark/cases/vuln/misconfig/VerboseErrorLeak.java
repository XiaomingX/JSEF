/*
 * JSEF Benchmark 样本 — 详细错误泄露（A05，CWE-209，L2）
 * 运行态需 JSEF 依赖（Spring MVC）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实信息收集利用。
 *
 * 知识点（A05 安全配置错误，CWE-209 错误信息暴露敏感信息）：
 *   异常堆栈/内部消息直接返回客户端，泄露实现细节、路径、SQL 等，助长进一步攻击。
 */
public class VerboseErrorLeak {

    /**
     * 危险入口：异常堆栈返回客户端。
     */
    static String handle(Exception ex) {
        // [CHECKPOINT id=JSEF-A05-002 cwe=209 level=L2 source=exception sink=response body (stack trace to client) expect=VULN]
        return ex.toString() + "\n" + stackTrace(ex);   // 泄露内部细节
    }

    static String stackTrace(Exception ex) {
        StringBuilder sb = new StringBuilder();
        for (StackTraceElement e : ex.getStackTrace()) sb.append(e).append("\n");
        return sb.toString();
    }
}
