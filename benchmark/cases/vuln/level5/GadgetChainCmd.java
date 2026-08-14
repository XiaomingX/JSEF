package com.jsef.benchmark.vuln;

import java.util.function.Function;

/**
 * JSEF-Benchmark L5 — gadget chain（CWE-78 Command Injection）
 *
 * 多个"单独安全"的处理器按序组合，把不可信片段最终拼接入命令执行 sink：
 *   - ConstantBuilder   ~ 返回固定命令前缀（无害）
 *   - Normalizer        ~ 字符串归一化（无害，仅做大小写/空格整理）
 *   - FieldExtractor    ~ 从不可信对象提取字段（无害，纯取值）
 *   - CommandAssembler  ~ 把上述结果拼接成最终命令（危险）
 *
 * 关键点（L5 难度）：每个处理器单看都"无害"——常量、归一化、取字段、拼接。
 * 但当它们经 ChainedProcessor 组合、并把链末端输出送入 Runtime.getRuntime().exec(...) 时，
 * 不可信字段一旦参与拼接链，就能拼出攻击者控制的命令，形成命令注入可达性。
 * 纯语法 SAST 难以识别跨类组合才危险的链路。
 *
 * 安全底线：本文件仅演示链式可达性语义，仅 localhost 演示，不提供真实利用载荷。
 *
 * CWE-78。
 */
public class GadgetChainCmd {

    @FunctionalInterface
    interface Processor extends Function<String, String> {
    }

    /** 返回固定命令前缀（无害）。 */
    static Processor constant(String prefix) {
        return x -> prefix;
    }

    /** 字符串归一化（无害，仅整理空格/小写）。 */
    static Processor normalize() {
        return s -> s == null ? "" : s.trim().toLowerCase();
    }

    /** 从不可信对象提取字段（无害，纯取值）。 */
    static String extractField(UntrustedInput in) {
        return in == null ? "" : in.getCommandFragment();
    }

    /** 危险处理器：拼接成最终命令（不可信片段进入）。 */
    static Processor assemble() {
        return cmd -> {
            // [CHECKPOINT id=JSEF-L5-CMD-001 cwe=78 level=L5 source=extracted untrusted fragment sink=Runtime.getRuntime().exec expect=VULN trace=benchmark/cases/vuln/level5/GadgetChainCmd.java:70,benchmark/cases/vuln/level5/GadgetChainCmd.java:71,benchmark/cases/vuln/level5/GadgetChainCmd.java:72,benchmark/cases/vuln/level5/GadgetChainCmd.java:73]
            return exec(cmd); // 不可信片段拼出的命令触发执行
        };
    }

    static String exec(String cmd) {
        // 语义等价：Runtime.getRuntime().exec(cmd)
        System.out.println("[cmd-exec] " + cmd);
        return "executed:" + cmd;
    }

    /** 不可信输入载体（仅 localhost 演示）。 */
    static class UntrustedInput {
        private final String commandFragment;
        UntrustedInput(String f) { this.commandFragment = f; }
        String getCommandFragment() { return commandFragment; }
    }

    /**
     * 构造危险 gadget chain：不可信字段经常量+归一化+拼接组合出命令，末端执行。
     */
    public static String buildAndTrigger(UntrustedInput input) {
        Processor chain = ignored -> {
            String cur = constant("ls -l ").apply(null);        // 常量前缀
            cur = normalize().apply(cur);                        // 归一化
            cur = cur + extractField(input);                     // 不可信字段拼入
            return assemble().apply(cur);                        // 末端 sink
        };
        return chain.apply("ignored");
    }

    public static void main(String[] args) {
        buildAndTrigger(new UntrustedInput("; id"));
    }
}
