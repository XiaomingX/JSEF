/*
 * JSEF Benchmark 样本 — 并发竞争安全对照 (CWE-362, L3)
 * 使用原子 CAS 循环保证 check-and-act 原子性。
 *
 * 修复要点（对照 vuln）：
 *   - compareAndSet(balance.get(), balance.get()-amount) 两次独立 get() 非原子，
 *     两次读之间余额可被其他线程修改 → 改为 CAS 循环，把 read+compute+write 捆绑为一次原子操作。
 *   - 同时加入余额充足性校验（防止扣成负数）。
 *
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import java.util.concurrent.atomic.AtomicLong;

public class RaceConditionSafe {

    static final AtomicLong balance = new AtomicLong(1000);

    static boolean withdraw(long amount) {
        if (amount <= 0) return false;
        long prev, next;
        do {
            prev = balance.get();
            if (prev < amount) return false; // 余额不足，拒绝（防负余额）
            next = prev - amount;
            // [CHECKPOINT id=JSEF-EXT-017S cwe=362 level=L3 source=withdraw request sink=atomic compareAndSet withdraw expect=SAFE]
        } while (!balance.compareAndSet(prev, next)); // CAS 循环：read→compute→write 原子捆绑
        return true;
    }
}
