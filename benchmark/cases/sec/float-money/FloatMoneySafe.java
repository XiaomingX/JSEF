package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L2 — 浮点金额比较修复（using BigDecimal.compareTo == 0）
 *
 * 安全侧：使用 BigDecimal 表示金额，并以 compareTo == 0 进行精确比较。
 * 按实现判定为安全。
 *
 * CWE-682 (Incorrect Calculation)。
 */
import java.math.BigDecimal;

public class FloatMoney {

    /**
     * 校验余额是否等于期望扣款金额（安全版）。
     *
     * @param balance       用户可控余额（字符串传入，避免 double 误差来源）
     * @param expectedAmount 期望金额（字符串）
     */
    public void verify(String balance, String expectedAmount) {
        BigDecimal a = new BigDecimal(balance);
        BigDecimal b = new BigDecimal(expectedAmount);
        // 安全修复：BigDecimal 精确比较，不受二进制浮点误差影响
        if (a.compareTo(b) == 0) {
            // [CHECKPOINT id=JSEF-NV302S cwe=682 level=L2 source=balance (double) sink=balance comparison (double ==) expect=SAFE]
            grant(a);
        }
    }

    // 抽象 sink：语义等价 放行/扣费
    static void grant(BigDecimal amount) {
        System.out.println("[grant] amount=" + amount);
    }

    public static void main(String[] args) {
        new FloatMoney().verify("0.3", "0.3");
    }
}
