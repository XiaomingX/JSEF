package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L2 — 三元运算符分支拼接污点
 *
 * 难度：L2（多跳 / 无断点）。三元运算符两分支都把不可信 x 拼接进命令，
 * 数据流经条件分支汇聚到同一 sink，纯语法 SAST 需同时追踪两分支。
 *
 * CWE-78 (OS Command Injection)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 TernaryDispatchSafe.java）：两分支均使用参数化 API，
 * 固定程序名，不拼接不可信 x。
 */
public class TernaryDispatch {

    /**
     * @param flag 控制分支
     * @param x    用户可控输入
     */
    public void run(boolean flag, String x) {
        // [CHECKPOINT id=JSEF-NV502 cwe=78 level=L2 source=x sink=Runtime.exec (ternary concat) expect=VULN]
        exec(flag ? "rm -rf " + x : "ls " + x);
    }

    // 抽象 sink：语义等价 Runtime.getRuntime().exec(cmd)
    static void exec(String cmd) {
        System.out.println("[cmd-exec] " + cmd);
    }

    public static void main(String[] args) {
        new TernaryDispatch().run(true, "$(touch /tmp/pwned)");
    }
}
