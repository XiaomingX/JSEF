// [VULN]
package com.jsef.benchmark.vuln;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import java.net.URL;

/**
 * JSEF-Benchmark — 子目标 B2-1：hostname 校验绕过 (CWE-295，难度 L2)
 *
 * ① 子目标清单：
 *    - 自定义 HostnameVerifier 的 verify() 恒返回 true；
 *    - 通过 HttpsURLConnection.setHostnameVerifier 安装该 verifier；
 *    - 任意域名/证书的主机名均被认为合法 → 中间人可伪造身份。
 *
 * ② 可达性说明：
 *    不可信源为网络对端的 TLS 握手主机名（attacker MITM），sink 为
 *    HostnameVerifier.verify() 恒真返回，SSLContext 据此跳过主机名匹配，
 *    数据流 attacker → verify() → true 直连，无中间断点。
 *
 * ③ 安全底线（仅 localhost 演示，无真实利用脚本）：
 *    本文件仅演示"恒真 verifier"的缺陷语义，不提供任何 MITM / 伪造证书脚本。
 *
 * ④ 修复要点：
 *    使用默认 HostnameVerifier（或严格校验域名与证书 SAN/CN），
 *    见 sec/HostnameVerifierBypass_Safe.java。
 */
public class HostnameVerifierBypass {

    /**
     * 危险：verify() 无条件返回 true，绕过主机名校验。
     */
    static HostnameVerifier bypassVerifier() {
        // [CHECKPOINT id=JSEF-HOST-001 cwe=295 level=L2 source=attacker MITM hostname sink=HostnameVerifier.verify(true) expect=VULN]
        return new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
    }

    /**
     * 危险：将恒真 verifier 安装到 HttpsURLConnection。
     */
    static void openInsecure(String url) throws Exception {
        HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
        conn.setHostnameVerifier(bypassVerifier());
        conn.connect();
    }
}
