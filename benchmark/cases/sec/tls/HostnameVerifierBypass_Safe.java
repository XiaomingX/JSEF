// [VULN]
package com.jsef.benchmark.sec;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import java.net.URL;

/**
 * JSEF-Benchmark — 子目标 B2-1 安全对照：hostname 严格校验 (CWE-295，SAFE)
 *
 * ① 子目标清单：
 *    - 不自定义 HostnameVerifier，依赖默认实现的主机名匹配；
 *    - 仅在确有需要时使用 javax.net.ssl.DefaultHostnameVerifier 严格校验。
 *
 * ② 可达性说明：
 *    无恒真绕过，主机名由 JVM 默认校验逻辑与证书 SAN/CN 比对，
 *    sink 不接收任意主机名为合法 → 不可达漏洞。
 *
 * ③ 安全底线（仅 localhost 演示，无真实利用脚本）：
 *    仅演示安全写法，不提供任何攻击脚本。
 *
 * ④ 修复要点：
 *    移除自定义恒真 verifier，使用默认/严格主机名校验。
 */
public class HostnameVerifierBypass_Safe {

    /**
     * 安全：使用默认 HostnameVerifier（不覆盖为恒真）。
     */
    static HostnameVerifier safeVerifier() {
        // [CHECKPOINT id=JSEF-HOST-001S cwe=295 level=L2 source=attacker MITM hostname sink=HostnameVerifier.verify(default) expect=SAFE]
        return javax.net.ssl.DefaultHostnameVerifierHolder.INSTANCE;
    }

    // 默认 verifier 持有者，避免依赖内部 API 名称歧义
    static final class DefaultHostnameVerifierHolder {
        static final HostnameVerifier INSTANCE = new HostnameVerifier() {
            private final javax.net.ssl.HostnameVerifier def = new javax.net.ssl.DefaultHostnameVerifier();
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return def.verify(hostname, session);
            }
        };
    }

    /**
     * 安全：连接时不安装自定义 verifier，使用默认校验。
     */
    static void openSafe(String url) throws Exception {
        HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
        // 不调用 setHostnameVerifier，保留 JVM 默认主机名校验
        conn.connect();
    }
}
