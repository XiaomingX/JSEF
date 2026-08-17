package com.jsef.benchmark.vuln;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/*
 * JSEF-Benchmark L2 — 无界任务队列堆积导致 OOM (CWE-400)
 *
 * 难度：L2（多跳）。task 来自用户请求，直接 put 进无容量上限的队列，
 * 攻击者高频提交使队列无限增长，最终内存耗尽。
 *
 * 安全底线：仅 localhost 演示语义。
 * 修复要点（UnboundedQueueSafe.java）：有界队列 + 拒绝策略。
 */
public class UnboundedQueueVuln {

    // [CHECKPOINT id=JSEF-NV406 cwe=400 level=L2 source=task sink=queue.put (unbounded queue OOM) expect=VULN]
    public void submit(Runnable task) throws Exception {
        // 无容量上限的队列，用户可无限堆积 → OOM
        BlockingQueue<Runnable> q = new LinkedBlockingQueue<>();
        q.put(task);
    }
}
