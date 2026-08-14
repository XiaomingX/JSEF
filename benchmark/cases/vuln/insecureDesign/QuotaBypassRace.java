/*
 * JSEF Benchmark 样本 — 并发配额绕过竞态（A04，CWE-362，L4）
 * 运行态需 JSEF 依赖（Spring MVC）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实竞态利用。
 *
 * 知识点（A04 不安全设计 / CWE-362 竞争条件）：
 *   配额校验后扣减（check-then-act）非原子，并发请求可同时越过校验、共同超额使用配额。
 *   数据流干净，但缺乏原子/锁保护：典型 TOCTOU 竞态。正确设计应加锁或原子操作。
 */
public class QuotaBypassRace {

    static int quotaRemaining = 100;

    /**
     * 危险入口：先查后扣，非原子，存在竞态。
     */
    static boolean consume(int used) {
        // source：不可信 used（请求参数）；sink：非原子 check-then-act 扣减
        // [CHECKPOINT id=JSEF-A04-004 cwe=362 level=L4 source=request used sink=quotaRemaining check-then-decrement (non-atomic) expect=VULN]
        if (quotaRemaining >= used) {          // 并发下多请求同时通过此校验
            quotaRemaining -= used;            // 竞态窗口：超额
            return true;
        }
        return false;
    }
}
