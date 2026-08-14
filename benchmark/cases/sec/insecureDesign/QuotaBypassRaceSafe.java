/*
 * JSEF Benchmark 安全样本 — 并发配额绕过竞态（A04，CWE-362，L4）
 * SAFE 版：校验与扣减置于同步块（原子 check-then-act），消除竞态窗口。
 * 测试点：强 SAST/LLM 应识别已加锁/原子而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
public class QuotaBypassRaceSafe {

    static int quotaRemaining = 100;

    /**
     * 安全入口：同步块内原子扣减。
     */
    static synchronized boolean consume(int used) {
        // 同步：并发请求串行化，杜绝超额
        // [CHECKPOINT id=JSEF-A04-004S cwe=362 level=L4 source=request used sink=synchronized quotaRemaining check-and-decrement expect=SAFE]
        if (quotaRemaining >= used) {
            quotaRemaining -= used;   // 原子，无竞态
            return true;
        }
        return false;
    }
}
