package com.jsef.benchmark.vuln;

import java.util.Optional;
import java.util.stream.Stream;

/*
 * JSEF-Benchmark L4 — Stream / Optional 隐式传播断链
 *
 * 难度：L4（隐式传播）。污点经 Optional.map / Stream 流水线隐式传递到 sink，
 * 中间无显式赋值给具名字段，纯语法工具难以跨 lambda 追踪数据流，易断链漏报。
 *
 * CWE-78 (OS Command Injection)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 StreamPropagationSafe.java）：在流处理前对输入做校验 /
 * 使用参数化 API，而非把不可信字符串拼接进命令。
 */
public class StreamPropagation {

    /**
     * 污点经 Optional + Stream 流水线进入命令拼接。
     *
     * @param userInput 用户可控输入
     */
    public void run(String userInput) {
        Optional.of(userInput)
                .map(s -> s)                       // 隐式传递
                .flatMap(s -> Stream.of(s))
                .forEach(cmd -> {
                    // [CHECKPOINT id=JSEF-TV-003 cwe=78 level=L4 source=userInput sink=Runtime.getRuntime().exec (via Stream.forEach) expect=VULN trace=benchmark/cases/vuln/taint-variants/StreamPropagation.java:25,benchmark/cases/vuln/taint-variants/StreamPropagation.java:31]
                    exec("sh -c " + cmd);          // 不可信 cmd 拼接进命令
                });
    }

    // 抽象 sink：语义等价 Runtime.getRuntime().exec(cmd)
    static void exec(String cmd) {
        System.out.println("[cmd-exec] " + cmd);
    }

    public static void main(String[] args) {
        new StreamPropagation().run("$(touch /tmp/pwned)");
    }
}
