package com.jsef.benchmark.sec;

import java.net.InetAddress;
import java.net.URL;
import java.net.HttpURLConnection;

/*
 * JSEF-Benchmark L4 — SSRF DNS 重绑定安全对照
 *
 * 修复：解析后绑定 IP 连接，使用 addr.getHostAddress() 避免二次解析，
 * 校验点 == 连接点。
 * SAFE 侧按实现判定安全。
 */
public class SsrfRebindSafe {

    public void run(String host) throws Exception {
        InetAddress addr = InetAddress.getByName(host);
        if (isInternal(addr)) {
            throw new IllegalArgumentException("internal host blocked");
        }
        URL url = new URL("http://" + addr.getHostAddress());  // 绑定已校验 IP
        // [CHECKPOINT id=JSEF-NV507S cwe=918 level=L4 source=host sink=openConnection (DNS rebind TOCTOU) expect=SAFE]
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.getInputStream();
    }

    static boolean isInternal(InetAddress addr) {
        byte[] ip = addr.getAddress();
        return ip[0] == 10 || (ip[0] == (byte) 192 && ip[1] == (byte) 168);
    }

    public static void main(String[] args) throws Exception {
        new SsrfRebindSafe().run("example.com");
    }
}
