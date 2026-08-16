/*
 * JSEF Benchmark 样本 — 并发竞争 TOCTOU (CWE-362, L3)
 * 检查余额后扣款（check-then-act），无原子性保护。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

public class RaceCondition {

    static long balance = 1000;

    // 危险：先查后扣，两操作间存在竞态窗口
    static boolean withdraw(long amount) {
        if (balance >= amount) { // check
            // [CHECKPOINT id=JSEF-EXT-017 cwe=362 level=L3 source=withdraw request sink=balance update after non-atomic check expect=VULN]
            balance -= amount; // act（并发下可超支）
            return true;
        }
        return false;
    }
}
