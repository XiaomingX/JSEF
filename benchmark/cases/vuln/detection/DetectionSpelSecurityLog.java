package com.jsef.benchmark.vuln.detection;

/**
 * JSEF-Benchmark 样本族 A：检测压力 / 规避监控 — SpEL 注入 + 安全日志（CWE-917，L4）
 *
 * 难度：L4（跨文件/跨编译单元：入口方法调用 SpelSecurityLogger 辅助类后入 SpEL 求值 sink）。
 *
 * 链路（source→sink）：
 *   1) userExpression                               (source：不可信，来自请求参数)
 *   2) securityLogger.logExpression(userExpression) (跨节点：把表达式 + 栈回溯写入安全日志)
 *   3) spelParse(userExpression)                    (sink：语义等价 SpelExpressionParser 求值)
 *
 * 为什么是检测压力（区别于现有 SpEL 注入样本）：
 *   危险 sink 确实可达（VULN 成立），但表达式在进入 SpEL 求值前被 SpelSecurityLogger
 *   （独立编译单元）连同调用栈写入安全日志——攻击者触发的表达式会被完整记录。
 *   被测对象需额外判断：该 SpEL 注入在真实运营中会留下安全日志，攻击可被追溯；
 *   但漏洞仍在（可达即 VULN），难点是"规避安全日志/栈回溯后才可隐蔽利用"。
 *
 * 修复要点（对照 DetectionUncheckedCmd.java）：
 *   sec 侧在表达式进入求值前增加安全沙箱校验（非法类引用即 throw），使危险求值
 *   不可达，故判 SAFE。本 vuln 侧未做沙箱校验，仅作安全日志观察，判定 VULN。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class DetectionSpelSecurityLog {

    private final SpelSecurityLogger securityLogger = new SpelSecurityLogger();

    /**
     * 对用户可控表达式执行 SpEL 求值，求值前经安全日志记录。
     *
     * @param userExpression 用户可控的 SpEL 表达式文本
     * @return 求值结果
     */
    public Object evaluate(String userExpression) {
        // 跨节点：安全日志记录表达式 + 栈回溯（见 SpelSecurityLogger.java:24）
        securityLogger.logExpression(userExpression);
        // [CHECKPOINT id=JSEF-DE-004 cwe=917 level=L4 source=userExpression sink=spelParse(userExpression) semantically SpEL evaluation expect=VULN trace=benchmark/cases/vuln/detection/SpelSecurityLogger.java:24,benchmark/cases/vuln/detection/DetectionSpelSecurityLog.java:37]
        return spelParse(userExpression);                       // 污点入 sink
    }

    // 抽象 sink：语义等价 SpelExpressionParser.parseExpression(expr).getValue(...)
    // 求值上下文暴露内部方法，可达 Runtime 等危险类（RCE），仅 localhost 打印
    static Object spelParse(String expr) {
        System.out.println("[spel-eval] " + expr);
        return "evaluated:" + expr;
    }
}
