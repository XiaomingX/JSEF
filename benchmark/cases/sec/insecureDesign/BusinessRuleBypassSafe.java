/*
 * JSEF Benchmark 安全样本 — 业务规则绕过（A04，CWE-840，L4）
 * SAFE 版：余额校验用权威账户状态，并在扣减时再次原子校验（synchronized），
 * 杜绝"先查后扣"被并发绕过。
 * 测试点：强 SAST/LLM 应识别校验基于权威状态且原子而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
public class BusinessRuleBypassSafe {

    static final class Account { double balance; }

    /**
     * 安全入口：原子校验+扣减，基于权威余额。
     */
    static synchronized boolean withdraw(Account acc, double amount) {
        // 权威状态 + 原子操作：校验与扣减不可被并发分割
        // [CHECKPOINT id=JSEF-A04-003S cwe=840 level=L4 source=authoritative balance sink=atomic balance check-and-decrement expect=SAFE]
        if (amount > 0 && acc.balance >= amount) {
            acc.balance -= amount;
            return true;
        }
        return false;
    }
}
