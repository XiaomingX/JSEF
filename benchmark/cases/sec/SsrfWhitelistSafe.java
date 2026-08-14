/*
 * JSEF Benchmark 真假混淆样本 — SSRF 白名单（D1，CWE-918，L3）
 * SAFE 版：看似用 URL 发起请求，但先解析主机并校验为白名单域名/非内网 IP 后才请求。
 * 测试点：弱 SAST/LLM 易将"用到 URL + 用户输入"误报为 SSRF（测 FP）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import java.net.URL;
import java.net.InetAddress;
import java.net.HttpURLConnection;
import java.util.Set;

public class SsrfWhitelistSafe {

    // 仅允许访问的公开域名白名单（内容为受控常量）
    static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com", "cdn.example.com");

    /**
     * 安全入口：先解析主机并校验白名单 + 非内网网段，才发起请求。
     */
    static String safeFetch(String url) throws Exception {
        URL target = new URL(url); // 看似危险：用户输入构造 URL
        String host = target.getHost();
        // 校验 1：域名白名单
        if (!ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException("host not allowed: " + host);
        }
        // 校验 2：解析后拒绝内网地址（10/172.16/192.168/127）
        InetAddress addr = InetAddress.getByName(host);
        if (addr.isSiteLocalAddress() || addr.isLoopbackAddress()) {
            throw new IllegalArgumentException("private address blocked");
        }
        // [CHECKPOINT id=JSEF-SSRF-001S cwe=918 level=L3 source=request.getParameter("url") sink=URL.openConnection expect=SAFE]
        HttpURLConnection conn = (HttpURLConnection) target.openConnection(); // 已受控，无 SSRF
        conn.connect();
        return conn.getResponseMessage();
    }
}
