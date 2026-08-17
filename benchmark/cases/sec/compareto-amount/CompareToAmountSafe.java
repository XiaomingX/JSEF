package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L2 — 字符串金额比较修复（using BigDecimal.compareTo）
 *
 * 安全侧：将金额字符串转为 BigDecimal，再以数值 compareTo 做比较。
 * 按实现判定为安全。
 *
 * CWE-682 (Incorrect Calculation)。
 */
import java.math.BigDecimal;

public class CompareToAmount {

    /**
     * 校验用户金额是否不超过限额（安全版）。
     *
     * @param userAmount  用户可控金额字符串
     * @param limitAmount 限额字符串
     */
    public void check(String userAmount, String limitAmount) {
        // 安全修复：转为 BigDecimal 做数值比较
        if (new BigDecimal(userAmount).compareTo(new BigDecimal(limitAmount)) <= 0) {
            // [CHECKPOINT id=JSEF-NV303S cwe=682 level=L2 source=amountStr sink=amount compare (lexicographic compareTo) expect=SAFE]
            allow(userAmount);
        }
    }

    // 抽象 sink：语义等价 放行转账
    static void allow(String amount) {
        System.out.println("[allow] amount=" + amount);
    }

    public static void main(String[] args) {
        new CompareToAmount().check("100", "99");
    }
}
