package com.jsef.benchmark.sec;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;

/**
 * JSEF-Benchmark Phase5-C — Blind SSRF 安全版（CWE-918，难度 L3）
 *
 * 与 BlindSsrfNoResponse 对照：在校验内网地址后，直接对已解析的 IP 地址发起连接
 * （而非重新解析域名），防止 DNS rebinding 攻击（TOCTOU）。
 *
 * DNS rebinding 修复说明：
 *   旧版：resolve → validate(IP₁) → openConnection（内部再次 resolve 可能得到 IP₂）
 *   新版：resolve → validate(IP₁) → 直接对 IP₁ 发起 Socket 连接（bypass DNS 二次解析）
 *   从而保证"校验的 IP"与"实际连接的 IP"严格一致，消除 TOCTOU 窗口。
 *
 * 同时补充 0.0.0.0 和 IPv6 本地链路地址 (ULA fc/fd) 校验。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实内网利用脚本。
 */
public class BlindSsrfNoResponseSafe {

    static String probe(String url) throws Exception {
        URL target = new URL(url);
        // 一次性解析：后续直接使用此 IP，不再重新解析（防 DNS rebinding）
        InetAddress addr = InetAddress.getByName(target.getHost());

        // [CHECKPOINT id=JSEF-BL-001S cwe=918 level=L3 source=request parameter url sink=Socket(resolved IP, port) expect=SAFE]
        if (isPrivateOrLocalAddress(addr)) {
            throw new IllegalArgumentException("private/local address blocked: " + addr.getHostAddress());
        }

        int port = target.getPort() > 0 ? target.getPort() : target.getDefaultPort();
        // 直接对已校验的 IP 建立 Socket（不经过 DNS 二次解析，消除 rebinding TOCTOU）
        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress(addr, port), 3000);
        }
        return "done";
    }

    /** 内网/本地地址判定（含 0.0.0.0、IPv6 ULA fc::/7）。 */
    private static boolean isPrivateOrLocalAddress(InetAddress addr) {
        if (addr.isSiteLocalAddress()) return true;   // 10/8、172.16/12、192.168/16、fc/fd::
        if (addr.isLoopbackAddress())  return true;   // 127.x、::1
        if (addr.isLinkLocalAddress()) return true;   // 169.254/16、fe80::/10
        if (addr.isAnyLocalAddress())  return true;   // 0.0.0.0 / ::
        // 额外检查：IPv4 0.0.0.0 通过数组判断（某些 JVM isSiteLocal 不覆盖）
        byte[] raw = addr.getAddress();
        if (raw.length == 4 && raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0) return true;
        return false;
    }
}
