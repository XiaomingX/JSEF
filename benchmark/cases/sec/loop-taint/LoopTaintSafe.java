package com.jsef.benchmark.sec;

import java.util.Arrays;
import java.util.List;

/*
 * JSEF-Benchmark L3 — 循环累积安全对照
 *
 * 修复：循环内逐段白名单校验（仅允许 [a-z0-9-]），非法字符拒绝。
 * SAFE 侧按实现判定安全。
 */
public class LoopTaintSafe {

    private static final List<String> ALLOWED = Arrays.asList("ls", "cat", "home", "tmp");

    public void run(String[] parts) {
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            if (!ALLOWED.contains(p)) {
                throw new IllegalArgumentException("illegal segment: " + p);
            }
            sb.append(p);
        }
        // [CHECKPOINT id=JSEF-NV504S cwe=78 level=L3 source=parts[] sink=Runtime.exec (loop-accumulated) expect=SAFE]
        exec(sb.toString());
    }

    // 抽象 sink：语义等价 Runtime.getRuntime().exec(cmd)
    static void exec(String cmd) {
        System.out.println("[cmd-exec] " + cmd);
    }

    public static void main(String[] args) {
        new LoopTaintSafe().run(new String[]{"ls", "home"});
    }
}
