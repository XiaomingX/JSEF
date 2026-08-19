package com.jsef.benchmark.vuln.detection;

/**
 * JSEF-Benchmark 样本族 A：检测压力 / 规避监控 — SpEL 注入 SAFE 对照（CWE-917，L4）
 *
 * 难度：L4（跨文件/含安全沙箱校验：表达式先过沙箱校验再入无害求值）。
 *
 * 链路（source→sink）：
 *   1) userExpression                               (source：不可信，来自请求参数)
 *   2) sandboxRejectIllegal(userExpression)         (安全节点：非法类引用即 throw)
 *   3) spelParseSafe(userExpression)                (安全 sink：被校验保护后的无害求值)
 *
 * 为什么是 SAFE（区别于 DetectionSpelSecurityLog.java 的 VULN 侧）：
 *   同是 SpEL 注入场景，但本样本的表达式在进入求值前先经过安全沙箱校验：
 *   任何对危险类/内部方法的引用（如 T(java.lang.Runtime)、T(ProcessBuilder) 等
 *   非法类引用）都会直接抛异常，使危险求值不可达。因此即使表达式来自不可信输入，
 *   sink 也不会被污染到危险语义 —— 判 SAFE（安全 sink 行：校验保护后的无害调用处）。
 *
 * 修复要点（对照 sec 侧思路）：
 *   与检测压力类样本互补——检测压力强调"监控可发现"但仍判 VULN；本 SAFE 对照
 *   强调的是"危险求值不可达"，从根上消除可利用性。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class DetectionUncheckedCmd {

    private static final String[] FORBIDDEN = {"Runtime", "ProcessBuilder", "Class.forName"};

    /**
     * 对用户可控表达式先做沙箱校验再求值；非法类引用即拒绝。
     *
     * @param userExpression 用户可控的 SpEL 表达式文本
     * @return 求值结果（仅安全子集可到达）
     */
    public Object evaluate(String userExpression) {
        // 安全节点：非法类引用即 throw，阻断危险可达性
        sandboxRejectIllegal(userExpression);
        // [CHECKPOINT id=JSEF-DE-004S cwe=917 level=L4 source=userExpression sink=spelParseSafe(userExpression) guarded by sandbox expect=SAFE]
        return spelParseSafe(userExpression);                  // 安全 sink：无害求值
    }

    /** 安全沙箱：表达式含非法类引用即抛异常，使危险求值不可达。 */
    static void sandboxRejectIllegal(String expr) {
        for (String bad : FORBIDDEN) {
            if (expr.contains(bad)) {
                throw new IllegalArgumentException("forbidden type reference: " + bad);
            }
        }
    }

    // 安全 sink：语义等价 SpEL 求值，但已被沙箱校验保护，无法触达危险类
    static Object spelParseSafe(String expr) {
        System.out.println("[spel-safe-eval] " + expr);
        return "evaluated:" + expr;
    }
}
