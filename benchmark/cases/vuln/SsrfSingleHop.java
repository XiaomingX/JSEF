/*
 * JSEF Benchmark 样本 — SSRF 单跳（D1，CWE-918，L1）
 * 运行态需 JSEF 依赖；本文件为独立 benchmark 源文件，使用标准 JDK 类表达 sink，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实内网攻击利用。
 */
import java.net.URL;
import java.net.HttpURLConnection;

public class SsrfSingleHop {

    /**
     * 危险入口：用户输入直接作为请求 URL，未做内网/白名单校验。
     */
    static String fetch(String url) throws Exception { // source：不可信 HTTP 参数
        // [CHECKPOINT id=JSEF-SSRF-001 cwe=918 level=L1 source=request.getParameter("url") sink=URL.openConnection expect=VULN]
        URL target = new URL(url);                     // 污点直连 sink：服务端请求伪造
        HttpURLConnection conn = (HttpURLConnection) target.openConnection();
        conn.connect();
        return conn.getResponseMessage();
    }
}
