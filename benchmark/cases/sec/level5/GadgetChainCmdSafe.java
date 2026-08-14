package com.jsef.benchmark.sec;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

/**
 * JSEF-Benchmark L5 — GadgetChainCmd 安全对照（SAFE 混淆样本）
 *
 * 安全做法：链末端对不可信字段做白名单截断——仅允许字母数字，且命令为固定参数列表，
 * 不可信片段永不进入 shell 拼接。用于计算 TN / FP。
 *
 * CWE-78。
 */
public class GadChainCmdSafe {

    @FunctionalInterface
    interface SafeProcessor extends Function<String, String> {
    }

    static SafeProcessor constant(String prefix) {
        return x -> prefix;
    }

    static SafeProcessor normalize() {
        return s -> s == null ? "" : s.trim().toLowerCase();
    }

    /** 白名单截断：仅保留字母数字，丢弃任何 shell 元字符。 */
    static String sanitize(String frag) {
        if (frag == null) return "";
        return frag.replaceAll("[^a-zA-Z0-9]", "");
    }

    static final List<String> ALLOWED = Arrays.asList("ls", "id", "date");

    static String execAllowed(String name) {
        // 语义等价：Runtime.getRuntime().exec(new String[]{name})，固定参数列表
        if (!ALLOWED.contains(name)) {
            System.out.println("[cmd-exec-safe] rejected: " + name);
            return "rejected";
        }
        System.out.println("[cmd-exec-safe] " + name);
        return "executed-safe:" + name;
    }

    public static String buildSafeChain(String untrusted) {
        SafeProcessor chain = ignored -> {
            String name = constant("").apply(null);            // 常量前缀
            name = normalize().apply(name + untrusted);         // 归一化
            name = sanitize(name);                              // 白名单截断
            // [CHECKPOINT id=JSEF-L5-CMD-001S cwe=78 level=L5 source=extracted untrusted fragment sink=Runtime.getRuntime().exec expect=SAFE]
            return execAllowed(name); // 不可信仅作白名单校验后的名字，不拼 shell
        };
        return chain.apply("ignored");
    }

    public static void main(String[] args) {
        buildSafeChain("; id");
    }
}
