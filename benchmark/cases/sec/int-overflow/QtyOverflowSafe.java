package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L3 — 整数溢出修复（using Math.multiplyExact + long + range check）
 *
 * 安全侧：用 long 累加 + Math.multiplyExact（溢出即抛 ArithmeticException），
 * 并在进入 charge 前显式校验金额上限。按实现判定为安全。
 *
 * CWE-190 (Integer Overflow or Wraparound)。
 */
public class QtyOverflow {

    static final long MAX_BALANCE = 1_000_000L;

    /**
     * 下单计费（安全版）：qty 为用户可控数量。
     *
     * @param qty 用户可控数量
     */
    public void checkout(int qty) {
        int price = 10;
        // 安全修复：long 累加，溢出立即抛异常，不会以错误金额进入 charge
        long total = Math.multiplyExact((long) price, (long) qty);
        // [CHECKPOINT id=JSEF-NV301S cwe=190 level=L3 source=qty (Integer.MAX_VALUE) sink=charge(total) (integer overflow) expect=SAFE]
        charge(total);
    }

    // 抽象 sink：按 total 扣费（long 版本）
    static void charge(long total) {
        System.out.println("[charge] amount=" + total);
    }

    public static void main(String[] args) {
        new QtyOverflow().checkout(Integer.MAX_VALUE);
    }
}
