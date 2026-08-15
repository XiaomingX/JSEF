package com.jsef.benchmark.vuln.perf;

/**
 * JSEF-Benchmark A2「代码质量/性能 DoS」— 循环内每轮大对象分配（L2）
 *
 * 子目标清单：
 *   ① 识别在 for 循环体内每轮都 new 一个大数组/大对象；
 *   ② 识别该模式如何制造大量短命大对象，迫使 GC 频繁 Full GC → 停顿放大；
 *   ③ 区分「循环内重复分配」与「循环外分配一次复用」（缓冲复用优化）；
 *   ④ 识别修复方向：把缓冲区提升到循环外分配一次并复用。
 *
 * 可达性说明：
 *   source = 外部传入的记录数 n（类比请求参数），进入 for 循环后每轮
 *   new byte[SIZE] 分配大数组，L2（循环 + 大对象分配两步语义）。
 *
 * 安全底线声明：
 *   仅 localhost 教学演示，不提供内存耗尽/GC 压测利用脚本，不针对真实服务。
 *
 * 修复要点（对照 LargeAllocInLoop_Safe.java）：
 *   在循环外分配一次缓冲区，循环内复用（必要时按偏移写入）。
 *
 * CWE-400（资源耗尽 / 不受控资源消耗）。
 */
public class LargeAllocInLoop {

    private static final int SIZE = 8 * 1024 * 1024; // 8MB 每轮

    /**
     * 每轮循环都分配一个 8MB 大数组，制造大量短命大对象触发频繁 Full GC。
     */
    public void process(int n) {
        for (int i = 0; i < n; i++) {
            // [CHECKPOINT id=JSEF-PERF-ALLOC-001 cwe=400 level=L2 source=requestParam(n) sink=new byte[] expect=VULN]
            // 缺陷：循环体内每轮分配大数组，短命大对象迫使 GC 频繁回收，吞吐骤降甚至 OOM
            byte[] buf = new byte[SIZE];
            consume(buf, i);
        }
    }

    private void consume(byte[] buf, int i) {
        // 语义占位：使用缓冲区
    }

    public static void main(String[] args) {
        new LargeAllocInLoop().process(10);
    }
}
