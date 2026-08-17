package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L2 — 字符串金额字典序比较绕过限额（lexicographic compareTo）
 *
 * 难度：L2（业务语义陷阱）。金额以字符串形式用 String.compareTo 做“不大于上限”
 * 的校验，compareTo 是字典序比较而非数值比较。字符串 "9" 字典序大于 "10"，
 * 因此用户金额 "9" 在数值上小于限额 "10" 却被判为超限不通过的反例之外，更危险的是
 * "100" 字典序小于 "99"（'1' < '9'），使本应超额的 "100" 误判为“不超过限额”而通过。
 *
 * CWE-682 (Incorrect Calculation)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 CompareToAmountSafe.java）：用 BigDecimal(userAmount).compareTo(...)
 * 做数值比较。
 */
public class CompareToAmount {

    /**
     * 校验用户金额是否不超过限额（字符串形式）。
     *
     * @param userAmount  用户可控金额字符串
     * @param limitAmount 限额字符串
     */
    public void check(String userAmount, String limitAmount) {
        // 危险终点：String.compareTo 为字典序比较，非数值比较
        if (userAmount.compareTo(limitAmount) <= 0) {
            // [CHECKPOINT id=JSEF-NV303 cwe=682 level=L2 source=amountStr sink=amount compare (lexicographic compareTo) expect=VULN]
            allow(userAmount);
        }
    }

    // 抽象 sink：语义等价 放行转账
    static void allow(String amount) {
        System.out.println("[allow] amount=" + amount);
    }

    public static void main(String[] args) {
        // 字典序："100" < "99" 成立 → 超额的 100 被误判为通过
        new CompareToAmount().check("100", "99");
    }
}
