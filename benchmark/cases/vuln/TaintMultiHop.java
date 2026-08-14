package com.jsef.benchmark.vuln;

import java.io.IOException;

/**
 * JSEF-Benchmark L2 — 多跳污点传播（变量无断点专项，命令注入）
 *
 * 难度：L2（多跳）。source → 中间变量 a → b → c（经字符串处理/拼接但不净化）→ sink。
 * 至少 3 个中间赋值。弱工具可能在中间断点丢失污点，强工具应保持污点不丢（CAP-04）。
 *
 * CWE-78 OS Command Injection。
 */
public class TaintMultiHop {

    /**
     * 多跳：userInput 经 3 次中间赋值与字符串处理，最终仍携带污点进入 sink。
     *
     * @param userInput 不可信输入
     */
    public void runCommand(String userInput) throws IOException {
        String a = userInput;                                  // 中间 1：直接透传
        String b = a + " ; echo localhost";                    // 中间 2：拼接（未净化）
        String c = b.trim();                                   // 中间 3：字符串处理（未净化）
        // [CHECKPOINT id=JSEF-TP-002 cwe=78 level=L2 source=userInput sink=Runtime.getRuntime().exec expect=VULN]
        Process p = Runtime.getRuntime().exec(c);
    }

    public static void main(String[] args) throws IOException {
        new TaintMultiHop().runCommand("ls -la");
    }
}
