package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L3 — 异常路径污点传播
 *
 * 难度：L3（跨方法 / 间接路径）。try 块抛出攻击者可控异常（如反射 / 反序列化
 * 失败消息），catch 块把 e.getMessage() 拼接进命令执行，污点经异常对象隐式
 * 跨越 try→catch 作用域，纯语法 SAST 易漏追踪。
 *
 * CWE-78 (OS Command Injection)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 ExceptionExecSafe.java）：catch 块使用固定命令，
 * 不拼接异常消息。
 */
public class ExceptionExec {

    /**
     * @param payload 用户可控可能触发异常的输入
     */
    public void run(String payload) {
        try {
            trigger(payload);
        } catch (Exception e) {
            // e.getMessage() 可能由不可信 payload 控制
            // [CHECKPOINT id=JSEF-NV503 cwe=78 level=L3 source=e.getMessage() sink=Runtime.exec (in catch) expect=VULN]
            exec("notify " + e.getMessage());
        }
    }

    static void trigger(String payload) {
        // 模拟：不可信 payload 导致异常，消息含 payload
        if (payload.contains("boom")) {
            throw new IllegalArgumentException("boom " + payload);
        }
    }

    // 抽象 sink：语义等价 Runtime.getRuntime().exec(cmd)
    static void exec(String cmd) {
        System.out.println("[cmd-exec] " + cmd);
    }

    public static void main(String[] args) {
        new ExceptionExec().run("boom; rm -rf /");
    }
}
