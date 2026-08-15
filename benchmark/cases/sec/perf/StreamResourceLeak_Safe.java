package com.jsef.benchmark.sec.perf;

import java.io.FileInputStream;
import java.io.IOException;

/**
 * JSEF-Benchmark A1「代码质量/性能 DoS」— 流资源泄漏安全对照（SAFE）
 *
 * 安全做法：try-with-resources 自动关闭 InputStream，无论正常还是异常，
 * 文件句柄均释放，避免 fd 耗尽 DoS。用于计算 TN（正确不报）/ FP（误报）。
 *
 * 修复要点（对照 StreamResourceLeak.java）：
 *   try-with-resources 包裹 InputStream。
 *
 * CWE-772 / CWE-404（资源泄漏 / 不当释放）。
 */
public class StreamResourceLeak_Safe {

    /**
     * 安全：try-with-resources 自动关闭流。
     *
     * @param path 外部传入路径（类比 @RequestParam path）
     */
    public void read(String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path)) {
            int b = in.read(); // 读取首字节仅作演示
            // [CHECKPOINT id=JSEF-PERF-IO-001S cwe=772 level=L1 source=path sink=new FileInputStream expect=SAFE]
        }
    }

    public static void main(String[] args) throws IOException {
        new StreamResourceLeak_Safe().read("/tmp/localhost-demo.txt");
    }
}
