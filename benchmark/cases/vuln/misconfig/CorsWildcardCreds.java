/*
 * JSEF Benchmark 样本 — CORS 通配符带凭证（A05，CWE-942，L3）
 * 运行态需 JSEF 依赖（Spring MVC / HttpServletResponse）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实跨域窃取利用。
 *
 * 知识点（A05 安全配置错误，CWE-942 过度宽松跨域策略）：
 *   响应头 Access-Control-Allow-Origin 设为 "*" 且 Access-Control-Allow-Credentials=true，
 *   任意网站可携带受害者凭证发起跨域请求并读取响应，导致凭证泄露。
 */
import java.util.Map;

public class CorsWildcardCreds {

    /**
     * 危险入口：CORS 通配符 + 允许凭证。
     */
    static Map<String, String> buildCorsHeaders() {
        // [CHECKPOINT id=JSEF-A05-001 cwe=942 level=L3 source=cors config sink=Access-Control-Allow-Origin:* + Credentials:true expect=VULN]
        return Map.of(
            "Access-Control-Allow-Origin", "*",            // 任意源
            "Access-Control-Allow-Credentials", "true");   // 且允许凭证 → 泄露
    }
}
