package com.jsef.benchmark.vuln;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * JSEF-Benchmark — 资源泄漏（CWE-404，L1 单跳）
 *
 * 打开的 InputStream 未在 finally / try-with-resources 中关闭，方法异常
 * 或提前返回时句柄泄漏，长期运行下耗尽文件描述符导致后续 IO 失败（DoS）。
 *
 * CodeQL 对应查询：java/input-resource-leak、java/resource-leak。
 *
 * 安全底线：仅 localhost 教学演示。
 *
 * 修复要点（对照 StreamLeakNoFinallySafe.java）：try-with-resources 自动关闭。
 */
public class StreamLeakNoFinally {

    /**
     * 单跳：打开流后未关闭即返回。
     *
     * @param path 文件路径（类比请求参数）
     */
    public String read(String path) throws IOException {
        InputStream in = new FileInputStream(path); // 语义演示
        byte[] buf = new byte[1024];
        int n = in.read(buf);
        // [CHECKPOINT id=JSEF-QL-005 cwe=404 level=L1 source=path sink=new FileInputStream expect=VULN]
        return n > 0 ? new String(buf, 0, n) : ""; // 缺陷：in 未关闭
    }

    public static void main(String[] args) throws IOException {
        System.out.println(new StreamLeakNoFinally().read("/tmp/demo.txt"));
    }
}
