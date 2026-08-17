package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L3 — 异常路径安全对照
 *
 * 修复：catch 块使用固定命令，不拼接异常消息。
 * SAFE 侧按实现判定安全。
 */
public class ExceptionExecSafe {

    public void run(String payload) {
        try {
            trigger(payload);
        } catch (Exception e) {
            // [CHECKPOINT id=JSEF-NV503S cwe=78 level=L3 source=e.getMessage() sink=Runtime.exec (in catch) expect=SAFE]
            exec("echo handled");
        }
    }

    static void trigger(String payload) {
        if (payload.contains("boom")) {
            throw new IllegalArgumentException("boom " + payload);
        }
    }

    // 抽象 sink：语义等价 Runtime.getRuntime().exec(cmd)
    static void exec(String cmd) {
        System.out.println("[cmd-exec] " + cmd);
    }

    public static void main(String[] args) {
        new ExceptionExecSafe().run("boom; rm -rf /");
    }
}
