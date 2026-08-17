package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L3 — 整数溢出绕过余额上限校验（integer overflow）
 *
 * 难度：L3（数值语义陷阱）。price * qty 用 int 乘法，当 qty = Integer.MAX_VALUE
 * 时乘积溢出为极小/负值，从而绕过 `if (total <= MAX_BALANCE)` 的金额上限校验，
 * 最终以错误（溢出后）金额进入 charge(total) 这个危险终点。
 *
 * CWE-190 (Integer Overflow or Wraparound)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 QtyOverflowSafe.java）：使用 Math.multiplyExact（溢出抛异常）
 * + long 累加 + 显式范围校验。
 */
public class QtyOverflow {

    static final int MAX_BALANCE = 1_000_000;

    /**
     * 下单计费：qty 为用户可控数量。
     *
     * @param qty 用户可控数量（意图传 Integer.MAX_VALUE 触发溢出）
     */
    public void checkout(int qty) {
        int price = 10;
        // 危险终点：int 乘法溢出后 total 为负/小值，绕过下方上限校验
        int total = price * qty;
        // [CHECKPOINT id=JSEF-NV301 cwe=190 level=L3 source=qty (Integer.MAX_VALUE) sink=charge(total) (integer overflow) expect=VULN]
        charge(total);
    }

    // 抽象 sink：语义等价 charge(total) —— 按 total 扣费
    static void charge(int total) {
        System.out.println("[charge] amount=" + total);
    }

    public static void main(String[] args) {
        new QtyOverflow().checkout(Integer.MAX_VALUE);
    }
}
