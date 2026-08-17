package com.jsef.benchmark.sec;

import java.util.Optional;
import java.util.stream.Stream;

/*
 * JSEF-Benchmark L4 — StreamPropagation 安全对照（SAFE 混淆样本）
 *
 * 安全做法：在流入流处理前对输入做白名单校验，命令使用数组形式参数化
 * （无 shell 解析），不可信输入无法注入额外参数。用于计算 TN / FP。
 *
 * CWE-78 (OS Command Injection)。
 */
public class StreamPropagationSafe {

    public void run(String userInput) {
        Optional.of(userInput)
                .filter(StreamPropagationSafe::isAllowed) // 进入流前校验
                .flatMap(s -> Stream.of(s))
                // [CHECKPOINT id=JSEF-TV-003S cwe=78 level=L4 source=userInput sink=Runtime.getRuntime().exec (via Stream.forEach, filtered) expect=SAFE]
                .forEach(this::execAllowed);              // 仅允许值，数组参数化
    }

    // 白名单：仅允许单一安全 token
    static boolean isAllowed(String s) {
        return s.matches("[a-zA-Z0-9_-]{1,32}");
    }

    // 抽象 sink（安全）：语义等价 Runtime.exec(String[])，无 shell 解释
    void execAllowed(String token) {
        System.out.println("[cmd-exec-safe] token=" + token);
    }

    public static void main(String[] args) {
        new StreamPropagationSafe().run("$(touch /tmp/pwned)");
    }
}
