package com.jsef.benchmark.sec;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * JSEF-Benchmark — 网络连接资源泄漏安全对照（CWE-404，SAFE）
 *
 * 安全做法：try-with-resources 关闭 InputStream，finally 中 disconnect()。
 *
 * 修复要点（对照 SocketLeak.java）：关闭流并断开连接。
 */
public class SocketLeakSafe {

    public void fetch(String endpoint) throws IOException {
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try (InputStream in = conn.getInputStream()) {
            int b = in.read();
            // [CHECKPOINT id=JSEF-QL-006S cwe=404 level=L2 source=endpoint sink=HttpURLConnection.getInputStream (closed) expect=SAFE]
        } finally {
            conn.disconnect();
        }
    }

    public static void main(String[] args) throws IOException {
        System.out.println("safe demo");
    }
}
