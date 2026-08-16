package com.jsef.benchmark.vuln;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * JSEF-Benchmark — 网络连接资源泄漏（CWE-404，L2 多跳）
 *
 * HttpURLConnection / Socket 建立后未调用 disconnect() 或关闭输入流，高并发
 * 调用下连接与 socket 句柄累积泄漏，触发连接池/文件描述符耗尽。
 *
 * CodeQL 对应查询：java/resource-leak（连接类）。
 *
 * 安全底线：仅 localhost 教学演示，目标固定为 localhost。
 *
 * 修复要点（对照 SocketLeakSafe.java）：try-with-resources 关闭 InputStream
 * 并 disconnect()。
 */
public class SocketLeak {

    /**
     * 多跳：openConnection -> getInputStream -> 未关闭。
     *
     * @param endpoint 目标端点（固定 localhost 演示）
     */
    public void fetch(String endpoint) throws IOException {
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        InputStream in = conn.getInputStream();
        int b = in.read(); // 读取数据...
        // [CHECKPOINT id=JSEF-QL-006 cwe=404 level=L2 source=endpoint sink=HttpURLConnection.getInputStream expect=VULN]
        // 缺陷：in 与 conn 均未关闭，连接泄漏
    }

    public static void main(String[] args) throws IOException {
        new SocketLeak().fetch("http://localhost:8080/health");
    }
}
