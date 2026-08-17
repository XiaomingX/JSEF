package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L3 — 循环累积污点隐式传播
 *
 * 难度：L3（跨方法 / 间接）。不可信 parts[] 在 for 循环中逐段 append 到
 * StringBuilder，污点被分散累积后整体进入命令执行 sink。纯语法 SAST 需跨循环
 * 识别"多次赋值累积到同一可变缓冲区"的污点汇聚，易漏报。
 *
 * CWE-78 (OS Command Injection)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 LoopTaintSafe.java）：循环内逐段白名单校验后再使用。
 */
public class LoopTaint {

    /**
     * @param parts 用户可控字符串数组
     */
    public void run(String[] parts) {
        StringBuilder sb = new StringBuilder();
        // [CHECKPOINT id=JSEF-NV504 cwe=78 level=L3 source=parts[] sink=Runtime.exec (loop-accumulated) expect=VULN trace=benchmark/cases/vuln/loop-taint/LoopTaintVuln.java:23,benchmark/cases/vuln/loop-taint/LoopTaintVuln.java:26]
        for (String p : parts) {
            sb.append(p);                  // 累积污点（trace 节点①）
        }
        exec(sb.toString());              // 累积结果进入 sink（trace 节点②）
    }

    // 抽象 sink：语义等价 Runtime.getRuntime().exec(cmd)
    static void exec(String cmd) {
        System.out.println("[cmd-exec] " + cmd);
    }

    public static void main(String[] args) {
        new LoopTaint().run(new String[]{"rm -rf ", "/", " ; touch /tmp/pwned"});
    }
}
