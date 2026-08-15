package com.jsef.benchmark.sec.perf;

/**
 * JSEF-Benchmark A2「代码质量/性能 DoS」— 持锁 sleep 安全对照（L2）
 *
 * 子目标清单（对照 SleepWithLock.java）：
 *   ① 识别延时/sleep 逻辑已被移出 synchronized 临界区；
 *   ② 确认临界区内只保留必须原子保护的共享状态更新，锁持有时间极短；
 *   ③ 识别可选的异步化方案（ScheduledExecutor）以彻底解耦；
 *   ④ 验证修复后并发请求无需在锁上长时间排队，吞吐恢复正常。
 *
 * 可达性说明：
 *   source = 外部请求触发 handleRequest()，临界区内仅做原子更新，
 *   sleep/延时在锁外执行，L2（临界区与延时分离两步语义）。
 *
 * 安全底线声明：
 *   仅 localhost 教学演示，不提供并发压测/DoS 利用脚本，不针对真实服务。
 *
 * 修复要点：
 *   把 Thread.sleep 移到 synchronized 块之外；或改用异步定时调度。
 *
 * CWE-410 / CWE-400（已规避）。
 */
public class SleepWithLock_Safe {

    private final Object lock = new Object();

    /**
     * 仅在临界区内做原子更新，sleep 移到锁外，避免持锁阻塞。
     */
    public void handleRequest(long userId) {
        synchronized (lock) {
            updateSharedState(userId);
        }
        // [CHECKPOINT id=JSEF-PERF-SLEEP-001S cwe=410 level=L2 source=request sink=Thread.sleep expect=SAFE]
        // 修复：sleep 在锁外执行，临界区仅做原子更新，锁持有时间极短，吞吐不受阻塞影响
        try {
            Thread.sleep(1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void updateSharedState(long userId) {
        // 语义占位：原子更新共享状态
    }

    public static void main(String[] args) {
        new SleepWithLock_Safe().handleRequest(1L);
    }
}
