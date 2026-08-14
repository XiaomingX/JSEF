// [VULN]
package com.jsef.benchmark.vuln;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;

/**
 * JSEF-Benchmark — TLS/SSL 证书校验绕过 (CWE-295，难度 L2)
 *
 * 危险入口：自定义 TrustManager 的 checkServerTrusted 为空实现，且
 * HostnameVerifier 恒返回 true，SSLContext 信任所有证书 → 中间人可伪造。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实 MITM 脚本。
 */
public class TlsVerificationBypass {

    /**
     * 危险：信任所有证书的 TrustManager + 恒真 HostnameVerifier。
     */
    static SSLSocketFactory trustAll() throws Exception {
        TrustManager[] tm = new TrustManager[]{
            new X509TrustManager() {
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // [CHECKPOINT id=JSEF-TLS-001 cwe=295 level=L2 source=attacker MITM sink=checkServerTrusted(empty) expect=VULN]
                    // 空实现：不校验服务端证书
                }
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tm, null);
        return ctx.getSocketFactory();
    }

    /**
     * 危险：HostnameVerifier 恒返回 true，跳过主机名校验。
     */
    static HostnameVerifier allowAllHost() {
        // [CHECKPOINT id=JSEF-TLS-002 cwe=295 level=L2 source=attacker MITM sink=HostnameVerifier(true) expect=VULN]
        return (hostname, session) -> true;
    }
}
