package com.jsef.benchmark.sec.perf;

/**
 * JSEF-Benchmark A2「代码质量/性能 DoS」— 循环大对象分配安全对照（L2）
 *
 * 子目标清单（对照 LargeAllocInLoop.java）：
 *   ① 识别缓冲区已在循环外分配一次；
 *   ② 确认循环内复用同一缓冲区（按偏移写入），无每轮 new 大对象；
 *   ③ 区分「复用缓冲」与「每轮重分配」对 GC 压力的差异；
 *   ④ 验证修复后短命大对象消失，Full GC 频率显著下降。
 *
 * 可达性说明：
 *   source = 外部传入的记录数 n，缓冲区在循环外分配，循环内复用，
 *   L2（循环外分配 + 循环内复用两步语义）。
 *
 * 安全底线声明：
 *   仅 localhost 教学演示，不提供内存耗尽/GC 压测利用脚本，不针对真实服务。
 *
 * 修复要点：
 *   缓冲复用——循环外分配一次，循环内按偏移写入复用。
 *
 * CWE-400（已规避）。
 */
public class LargeAllocInLoop_Safe {

    private static final int SIZE = 8 * 1024 * 1024; // 8MB，仅分配一次

    /**
     * 循环外分配一次缓冲区，循环内复用，避免大量短命大对象。
     */
    public void process(int n) {
        // [CHECKPOINT id=JSEF-PERF-ALLOC-001S cwe=400 level=L2 source=requestParam(n) sink=new byte[] expect=SAFE]
        // 修复：缓冲区在循环外分配一次并复用，循环内不再每轮 new 大数组，GC 压力可控
        byte[] buf = new byte[SIZE];
        for (int i = 0; i < n; i++) {
            reuse(buf, i);
        }
    }

    private void reuse(byte[] buf, int i) {
        // 语义占位：复用同一缓冲区
    }

    public static void main(String[] args) {
        new LargeAllocInLoop_Safe().process(10);
    }
}
