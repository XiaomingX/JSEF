package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L2 — 三元运算符安全对照
 *
 * 修复：两分支均使用参数化命令数组，固定程序名，不可信 x 仅作参数。
 * SAFE 侧按实现判定安全。
 */
public class TernaryDispatchSafe {

    public void run(boolean flag, String x) {
        // [CHECKPOINT id=JSEF-NV502S cwe=78 level=L2 source=x sink=Runtime.exec (ternary concat) expect=SAFE]
        exec(flag ? new String[]{"rm", "-rf", x} : new String[]{"ls", x});
    }

    // 抽象 sink：语义等价 Runtime.getRuntime().exec(String[]) 参数化
    static void exec(String[] cmd) {
        System.out.println("[cmd-exec] " + String.join(" ", cmd));
    }

    public static void main(String[] args) {
        new TernaryDispatchSafe().run(true, "$(touch /tmp/pwned)");
    }
}
