/*
 * JSEF Benchmark 样本 — 业务规则绕过（A04，CWE-840，L4）
 * 运行态需 JSEF 依赖（Spring MVC）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实绕过利用。
 *
 * 知识点（A04 不安全设计，CWE-840 业务逻辑错误）：
 *   转账前校验"余额充足"，但校验与扣减非原子、且可被并发/顺序绕过（先查后扣，
 *   中间状态被利用）。更根本的是：余额校验依赖可被篡改的入参而非权威账户状态。
 *   数据流干净，但业务规则（余额约束）设计缺失/可被绕过。
 */
public class BusinessRuleBypass {

    static final class Account { double balance; }

    /**
     * 危险入口：余额校验可被绕过（校验用不可信 amount 而非权威状态）。
     */
    static boolean withdraw(Account acc, double amount) {
        // source：不可信 amount（请求参数）；sink：扣减前校验可被绕过
        // [CHECKPOINT id=JSEF-A04-003 cwe=840 level=L4 source=request amount sink=balance check before withdraw (bypassable) expect=VULN]
        if (amount > 0 && acc.balance >= amount) {   // 可被并发/顺序绕过
            acc.balance -= amount;
            return true;
        }
        return false;
    }
}
