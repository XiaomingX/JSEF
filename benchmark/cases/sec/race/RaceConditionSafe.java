/*
 * JSEF Benchmark 样本 — 并发竞争安全对照 (CWE-362, L3)
 * 使用同步 / 原子 CAS 保证 check-and-act 原子性。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import java.util.concurrent.atomic.AtomicLong;

public class RaceConditionSafe {

    static final AtomicLong balance = new AtomicLong(1000);

    static boolean withdraw(long amount) {
        // [CHECKPOINT id=JSEF-EXT-017S cwe=362 level=L3 source=withdraw request sink=atomic compareAndSet withdraw expect=SAFE]
        return balance.compareAndSet(balance.get(), balance.get() - amount); // 原子扣款
    }
}
