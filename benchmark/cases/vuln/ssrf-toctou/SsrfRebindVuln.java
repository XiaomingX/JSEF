package com.jsef.benchmark.vuln;

import java.net.InetAddress;
import java.net.URL;
import java.net.HttpURLConnection;

/*
 * JSEF-Benchmark L4 — SSRF DNS 重绑定 (TOCTOU)
 *
 * 难度：L4（跨方法 / 状态机 + 框架语义）。先解析 host 得到 InetAddress 做内网
 * 校验，但连接时再次用 host 名解析，攻击者利用 DNS 重绑定使校验时解析到外网、
 * 连接时解析到内网（TOCTOU：校验点 ≠ 连接点）。纯语法 SAST 难以识别"两次解析
 * 结果不一致"这一语义缺口。
 *
 * CWE-918 (SSRF)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 SsrfRebindSafe.java）：解析后绑定 IP 连接，
 * 用 addr.getHostAddress() 避免二次解析。
 */
public class SsrfRebind {

    /**
     * @param host 用户可控主机名
     */
    public void run(String host) throws Exception {
        InetAddress addr = InetAddress.getByName(host);   // 校验时解析（trace 节点①）
        if (isInternal(addr)) {
            throw new IllegalArgumentException("internal host blocked");
        }
        URL url = new URL("http://" + host);   // 连接时二次解析 → 可重绑定内网
        // [CHECKPOINT id=JSEF-NV507 cwe=918 level=L4 source=host sink=openConnection (DNS rebind TOCTOU) expect=VULN trace=benchmark/cases/vuln/ssrf-toctou/SsrfRebindVuln.java:27,benchmark/cases/vuln/ssrf-toctou/SsrfRebindVuln.java:33]
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();   // 连接点（trace 节点②）
        conn.getInputStream();
    }

    static boolean isInternal(InetAddress addr) {
        byte[] ip = addr.getAddress();
        return ip[0] == 10 || (ip[0] == (byte) 192 && ip[1] == (byte) 168);
    }

    public static void main(String[] args) throws Exception {
        new SsrfRebind().run("evil.example.com");
    }
}
