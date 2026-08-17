package com.jsef.benchmark.sec;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;

/*
 * JSEF-Benchmark L2 — 无界队列修复 (CWE-400) expect=SAFE
 *
 * sec 侧：使用有界 ArrayBlockingQueue<>(MAX)，配合拒绝策略，
 * 队列满时新任务被拒绝而非无限堆积，避免 OOM。
 *
 * 安全底线：按实现判定为安全。
 */
public class UnboundedQueueSafe {

    static final int MAX = 1024;

    // [CHECKPOINT id=JSEF-NV406S cwe=400 level=L2 source=task sink=queue.put (bounded + reject) expect=SAFE]
    public void submit(Runnable task) throws Exception {
        // 有界队列 + 拒绝策略，满则拒绝，不堆积至 OOM
        BlockingQueue<Runnable> q = new ArrayBlockingQueue<>(MAX);
        RejectedExecutionHandler reject = new ThreadPoolExecutor.AbortPolicy();
        ThreadPoolExecutor exec = new ThreadPoolExecutor(2, 2, 0L,
                java.util.concurrent.TimeUnit.MILLISECONDS, q, reject);
        exec.submit(task);
    }
}
