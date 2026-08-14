// [SAFE]
package com.jsef.benchmark.sec;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;

/**
 * JSEF-Benchmark — TLS/SSL 证书校验安全对照 (CWE-295，难度 L2)
 *
 * 修复：使用默认信任链（系统 CA）校验服务端证书，并启用严格主机名校验，
 * 不自定义 TrustManager / HostnameVerifier。
 */
public class TlsVerificationBypassSafe {

    /**
     * 安全：使用 JVM 默认 SSLSocketFactory，依赖默认信任链 + 默认 hostname 校验。
     */
    static SSLSocketFactory safeFactory() throws Exception {
        // [CHECKPOINT id=JSEF-TLS-001S cwe=295 level=L2 source=default trust chain sink=HttpsURLConnection default SSLEngine expect=SAFE]
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        return sf;
    }
}
