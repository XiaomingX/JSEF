package com.jsef.benchmark.vuln.perf;

/**
 * JSEF-Benchmark A2「代码质量/性能 DoS」— 持锁 sleep 导致吞吐骤降（L2）
 *
 * 子目标清单：
 *   ① 识别在 synchronized 临界区内调用 Thread.sleep(ms) 的反模式；
 *   ② 识别该模式如何让持锁线程阻塞，使其他线程在锁上排队等待 → 并发吞吐骤降；
 *   ③ 区分「持锁 sleep」（CWE-410 不当资源释放/锁持有过久）与纯 CPU 忙等；
 *   ④ 识别修复方向：把 sleep 移出临界区，或改为异步/定时调度。
 *
 * 可达性说明：
 *   source = 外部请求触发 handleRequest()（类比 Controller 入口），进入
 *   synchronized(lock) 临界区后在锁内调用 Thread.sleep()，
 *   L2（临界区 + sleep 两步语义，锁持有时间被人为拉长）。
 *
 * 安全底线声明：
 *   仅 localhost 教学演示，不提供并发压测/DoS 利用脚本，不针对真实服务。
 *
 * 修复要点（对照 SleepWithLock_Safe.java）：
 *   将 sleep / 延时逻辑移出 synchronized 临界区，或改用异步调度（如 ScheduledExecutor）。
 *
 * CWE-410（不当资源释放 / 持锁过久）/ CWE-400（资源耗尽）。
 */
public class SleepWithLock {

    private final Object lock = new Object();

    /**
     * 在持锁状态下 sleep：阻塞期间其他线程无法进入临界区，吞吐骤降。
     */
    public void handleRequest(long userId) {
        synchronized (lock) {
            // 模拟一些需要原子保护的共享状态更新
            updateSharedState(userId);
            // [CHECKPOINT id=JSEF-PERF-SLEEP-001 cwe=410 level=L2 source=request sink=Thread.sleep expect=VULN]
            // 缺陷：持锁状态下 sleep，使锁被长时间占用，并发请求在 lock 上排队 → 吞吐量骤降 / 近似 DoS
            try {
                Thread.sleep(1000L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void updateSharedState(long userId) {
        // 语义占位：原子更新共享状态
    }

    public static void main(String[] args) {
        new SleepWithLock().handleRequest(1L);
    }
}
