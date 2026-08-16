package com.jsef.benchmark.sec;

import java.io.IOException;
import java.io.InputStream;

/**
 * JSEF-Benchmark — 资源泄漏安全对照（CWE-404，SAFE）
 *
 * 安全做法：try-with-resources 保证流在任何路径下关闭。
 *
 * 修复要点（对照 StreamLeakNoFinally.java）：try-with-resources 包裹流。
 */
public class StreamLeakNoFinallySafe {

    public String read(String path) throws IOException {
        try (InputStream in = open(path)) {
            byte[] buf = new byte[1024];
            int n = in.read(buf);
            // [CHECKPOINT id=JSEF-QL-005S cwe=404 level=L1 source=path sink=new FileInputStream (try-with-resources) expect=SAFE]
            return n > 0 ? new String(buf, 0, n) : "";
        }
    }

    private InputStream open(String path) throws IOException {
        return new java.io.ByteArrayInputStream("localhost-demo".getBytes());
    }

    public static void main(String[] args) throws IOException {
        System.out.println(new StreamLeakNoFinallySafe().read("/tmp/demo.txt"));
    }
}
